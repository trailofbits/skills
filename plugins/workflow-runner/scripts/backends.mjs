import { spawnSync } from 'node:child_process';
import { accessSync, constants, existsSync, mkdirSync } from 'node:fs';
import { lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { RunnerError } from './errors.mjs';
import { runProcess } from './process.mjs';
import { strictSchema, restoreOptional, parseStructured } from './schema.mjs';

export const BACKENDS = ['codex', 'gemini'];
export const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];
const CLAUDE_MODEL = /^(opus|sonnet|haiku|fable)\b|^claude-/i;
const WRITE_TOOLS = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit'];

// A scoped tool such as Bash(git log:*) counts as its base tool.
const toolBase = tool => tool.replace(/\(.*$/, '');
export const roleWrites = role => Boolean(role?.tools?.some(tool => WRITE_TOOLS.includes(toolBase(tool))));
export const roleRunsCommands = role => !role?.tools || role.tools.some(tool => toolBase(tool) === 'Bash');

// Exactly one host marker must be present. Nested sessions can carry several,
// and guessing would silently run a different provider than the user chose.
export function detectBackend(env) {
  const found = [env.CODEX_THREAD_ID && 'codex', env.GEMINI_CLI === '1' && 'gemini'].filter(Boolean);
  if (found.length === 1) return found[0];
  if (!found.length && env.CLAUDECODE === '1') {
    throw new RunnerError('CONFIG', 'Inside Claude Code, run the workflow with the native Workflow tool; workflow-runner is for hosts without one');
  }
  throw new RunnerError('CONFIG', found.length ? `Several host markers present (${found.join(', ')}); pass --backend` : 'No host detected; pass --backend codex or gemini');
}

// Workflows are written for Claude Code and name Claude models. Elsewhere those
// names mean "the CLI's configured default", announced once, rather than a
// failure on every call: a run on Codex should not need a model flag to start.
export function resolveModel(backend, { override, requested }) {
  if (override) return { model: override };
  if (!requested || requested === 'inherit') return {};
  if (CLAUDE_MODEL.test(requested)) {
    return { note: `Workflow asks for Claude model "${requested}"; ${backend} workers use the CLI's configured model (choose one with --model).` };
  }
  return { model: requested };
}

export function resolveEffort(backend, { override, requested }) {
  const effort = override ?? requested;
  if (!effort || effort === 'default') return {};
  if (!EFFORTS.includes(effort)) throw new RunnerError('CONFIG', `Unsupported effort ${effort}; use ${EFFORTS.join(', ')}`);
  if (backend === 'gemini') return { note: 'Gemini CLI has no reasoning-effort setting; effort hints are ignored.' };
  if (backend === 'codex' && effort === 'max') return { effort: 'xhigh', note: 'Codex has no "max" effort; using xhigh.' };
  return { effort };
}

// Tools that keep a cache in the home directory refuse to run when a Codex
// worker's sandbox cannot write it: uv cannot take its cache lock, and CodeQL
// cannot unpack query packs. An interactive session would ask the user to run
// such a command outside the sandbox; a headless worker cannot ask.
// Absolute PATH entries only: after an escalated launch the runner runs outside the sandbox
// with the target as its working directory, so a relative entry such as `.` would run the
// target's binaries.
export function findExecutable(name, env) {
  if (name.includes('/')) return path.resolve(name);
  for (const dir of (env.PATH ?? '').split(path.delimiter)) {
    if (!path.isAbsolute(dir)) continue;
    try { accessSync(path.join(dir, name), constants.X_OK); return path.join(dir, name); } catch { /* not here */ }
  }
  return null;
}

// Granted for each tool the workflow's plugin uses and that is on PATH, and created when
// missing: a first run is exactly when the tool needs to create its cache, as CodeQL does
// with ~/.codeql. A plugin that never mentions a tool gets no write access to its cache.
export function toolCaches(env, pluginText) {
  const home = env.HOME ?? os.homedir();
  const uses = { uv: /\buvx?\b/.test(pluginText), codeql: /\bcodeql\b/i.test(pluginText), semgrep: /\bsemgrep\b/i.test(pluginText) };
  const onPath = name => uses[name] && findExecutable(name, env) !== null;
  const dirs = [];
  const uvPath = uses.uv && findExecutable('uv', env);
  if (uvPath) {
    const uv = spawnSync(uvPath, ['cache', 'dir'], { env, encoding: 'utf8', timeout: 10_000 });
    if (uv.status === 0 && uv.stdout.trim()) dirs.push(uv.stdout.trim());
  }
  if (onPath('codeql')) dirs.push(path.join(home, '.codeql'));
  if (onPath('semgrep')) dirs.push(path.join(home, '.semgrep'));
  for (const dir of dirs) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dirs;
}

// A worker started inside the session's sandbox cannot write ~/.codex, which Codex needs
// at startup. It gets its own Codex folder instead, linking to the user's login and
// settings, which it only reads.
export async function prepareCodexHome(dir, env) {
  const real = env.CODEX_HOME ?? path.join(env.HOME ?? os.homedir(), '.codex');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  for (const file of ['auth.json', 'config.toml']) {
    const link = path.join(dir, file);
    if (!existsSync(path.join(real, file)) || await lstat(link).then(() => true, () => false)) continue;
    await symlink(path.join(real, file), link);
  }
  return dir;
}

// Inside the session's sandbox, uv and Semgrep cannot write their usual caches; these send
// them to a folder the sandbox allows, kept between runs so packages are not fetched every
// time. CodeQL needs nothing: it reads its bundled query packs in place.
export const toolCacheEnv = root => ({
  UV_CACHE_DIR: path.join(root, 'uv'),
  UV_TOOL_DIR: path.join(root, 'uv-tools'),
  SEMGREP_LOG_FILE: path.join(root, 'semgrep', 'semgrep.log'),
  SEMGREP_VERSION_CACHE_PATH: path.join(root, 'semgrep', 'version'),
});

export function commandArgs(backend, job) {
  const { sandbox, addDirs = [], cacheDirs = [], readDirs = [], network = false, certFile, model, effort, schemaPath, answerPath } = job;
  const writable = sandbox === 'workspace-write';
  if (backend === 'codex') {
    // No approval override: `codex exec` already refuses to prompt unless the user's
    // config routes approvals to Codex's automatic reviewer, which workers then use too.
    // Inside the session's sandbox a worker cannot apply a sandbox of its own (macOS refuses
    // a second one), so it runs without one, confined by the session's.
    const args = ['exec', '--json', '--color', 'never', '--ephemeral', '--skip-git-repo-check', '--cd', job.cwd,
      '--sandbox', job.insideSandbox ? 'danger-full-access' : sandbox, '--disable', 'multi_agent'];
    if (writable && !job.insideSandbox) {
      args.push('--config', `sandbox_workspace_write.network_access=${network}`);
      for (const dir of [...addDirs, ...cacheDirs]) args.push('--add-dir', dir);
    }
    // Set for the commands the worker runs, not for the codex binary, whose own TLS
    // keeps reading the keychain (corporate certificate authorities included).
    const shellEnv = { ...(certFile ? { SSL_CERT_FILE: certFile } : {}), ...(job.toolEnv ?? {}) };
    for (const [name, value] of Object.entries(shellEnv)) args.push('--config', `shell_environment_policy.set.${name}=${JSON.stringify(value)}`);
    if (model) args.push('--model', model);
    if (effort) args.push('--config', `model_reasoning_effort=${JSON.stringify(effort)}`);
    if (schemaPath) args.push('--output-schema', schemaPath);
    args.push('--output-last-message', answerPath, '-');
    return args;
  }
  const args = ['--output-format', 'json', '--approval-mode', { 'read-only': 'default', 'workspace-write': 'auto_edit', 'danger-full-access': 'yolo' }[sandbox]];
  if (model) args.push('--model', model);
  for (const dir of [...readDirs, ...(writable ? addDirs : [])]) args.push('--include-directories', dir);
  return args;
}

const parseJson = text => {
  try { return JSON.parse(text); }
  catch { throw new RunnerError('PROTOCOL', 'Worker CLI printed malformed JSON'); }
};
const count = n => Number.isSafeInteger(n) && n >= 0 ? n : null;
const sum = values => values.length && values.every(v => v !== null) ? values.reduce((a, b) => a + b, 0) : null;
const reason = value => typeof value === 'string' ? value : typeof value?.message === 'string' ? value.message : JSON.stringify(value ?? '');

export function decode(backend, stdout, answer) {
  if (backend === 'codex') {
    const events = stdout.split(/\r?\n/).filter(line => line.trim().startsWith('{')).map(parseJson);
    const completed = events.filter(event => event.type === 'turn.completed');
    const meta = {
      outputTokens: sum(completed.map(event => count(event.usage?.output_tokens))),
      sessionId: events.find(event => event.type === 'thread.started')?.thread_id ?? null,
      diagnostics: events.filter(event => event.type === 'error' || event.item?.type === 'error').map(event => reason(event.item ?? event)),
    };
    // Transient stream errors can precede a turn that still completes; only a
    // failed turn, or no completed turn at all, is a worker failure.
    const failed = events.find(event => event.type === 'turn.failed');
    if (failed || !completed.length) {
      throw new RunnerError('WORKER', `Codex worker failed: ${reason(failed?.error ?? meta.diagnostics.at(-1) ?? 'no completed turn')}`, meta);
    }
    const text = answer ?? events.filter(event => event.item?.type === 'agent_message').at(-1)?.item.text;
    if (typeof text !== 'string' || !text.trim()) throw new RunnerError('PROTOCOL', 'Codex worker produced an empty answer', meta);
    return { ...meta, text };
  }
  const result = parseJson(stdout);
  // Gemini reports visible and thinking tokens separately; both are output.
  const geminiOutput = tokens => {
    const visible = count(tokens?.candidates);
    const thinking = count(tokens?.thoughts ?? 0);
    return visible === null || thinking === null ? null : visible + thinking;
  };
  const meta = {
    outputTokens: sum(Object.values(result.stats?.models ?? {}).map(m => geminiOutput(m?.tokens))),
    sessionId: result.session_id ?? null,
  };
  if (result.error) throw new RunnerError('WORKER', `Gemini worker failed: ${reason(result.error)}`, meta);
  if (typeof result.response !== 'string' || !result.response.trim()) throw new RunnerError('PROTOCOL', 'Gemini worker produced an empty answer', meta);
  return { ...meta, text: result.response };
}

const record = (directory, name, content) => writeFile(path.join(directory, name), content ?? '', { mode: 0o600 });

// Runs one agent() call as a fresh CLI process and returns its value. The
// runtime validates the value against the workflow's own schema afterwards.
export async function executeWorker(job, context) {
  const { backend, directory } = job;
  const answerPath = path.join(directory, 'answer.txt');
  let prompt = job.prompt;
  let schemaPath;
  if (job.schema && backend === 'codex') {
    schemaPath = path.join(directory, 'output-schema.json');
    await record(directory, 'output-schema.json', JSON.stringify(strictSchema(job.schema), null, 2));
  }
  if (job.schema && backend === 'gemini') {
    prompt += `\n\nReply with only a JSON value matching this JSON Schema: no prose before or after it.\n${JSON.stringify(job.schema)}`;
  }
  await record(directory, 'prompt.txt', prompt);
  const args = commandArgs(backend, { ...job, schemaPath, answerPath });
  await record(directory, 'command.json', JSON.stringify([findExecutable(context.executable, job.env) ?? context.executable, ...args], null, 2));
  // Output is recorded on failure too: it is how a failed worker gets diagnosed.
  const executable = findExecutable(context.executable, job.env);
  if (!executable) throw new RunnerError('LAUNCH', `${context.executable} not found on PATH`);
  const output = await runProcess(executable, args, { cwd: job.cwd, env: job.env, input: prompt, timeoutMs: context.timeoutMs, signal: context.signal })
    .catch(async error => {
      await record(directory, 'stdout.txt', error.stdout);
      await record(directory, 'stderr.txt', error.stderr);
      throw error;
    });
  await record(directory, 'stdout.txt', output.stdout);
  await record(directory, 'stderr.txt', output.stderr);
  let answer;
  if (backend === 'codex') {
    try { answer = await readFile(answerPath, 'utf8'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const decoded = decode(backend, output.stdout, answer);
  let value = decoded.text;
  if (job.schema) {
    try {
      if (backend === 'codex') value = restoreOptional(parseStructured(decoded.text), job.schema);
      else value = parseStructured(decoded.text);
      if (value === undefined) throw new RunnerError('SCHEMA', 'Worker returned no structured result');
    } catch (error) {
      throw Object.assign(error, { outputTokens: decoded.outputTokens, sessionId: decoded.sessionId, diagnostics: decoded.diagnostics });
    }
  }
  return { value, outputTokens: decoded.outputTokens, sessionId: decoded.sessionId, diagnostics: decoded.diagnostics ?? [] };
}
