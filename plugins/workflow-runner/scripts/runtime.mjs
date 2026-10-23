import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { readFile, writeFile, mkdir, rename, unlink, readdir, realpath, rm } from 'node:fs/promises';
import { RunnerError, isWorkerFailure } from './errors.mjs';
import { digest, loadRegistry, resolveRole } from './definitions.mjs';
import { checkSchema, validate } from './schema.mjs';
import { BACKENDS, executeWorker, prepareCodexHome, resolveModel, resolveEffort, roleWrites, roleRunsCommands, toolCacheEnv, toolCaches } from './backends.mjs';

// Codex's sandbox modes. Workers take the mode of the session that launched them,
// as Codex's own subagents and Claude Code's workflow agents do.
export const SANDBOXES = ['read-only', 'workspace-write', 'danger-full-access'];
const OPTIONS = new Set(['schema', 'label', 'phase', 'model', 'effort', 'agentType']);
const RUNTIME_FILES = ['runtime.mjs', 'backends.mjs', 'definitions.mjs', 'schema.mjs', 'process.mjs', 'errors.mjs'];
const MAX_ITEMS = 4096;
const STATE_VERSION = 3;

// The settings that define a run. They are saved in state.json, so a resume
// needs only the run directory and cannot drift from the original invocation.
export const SETTINGS = ['script', 'args', 'cwd', 'backend', 'sandbox', 'addDirs', 'network', 'pluginRoots',
  'model', 'effort', 'concurrency', 'maxAgents', 'timeoutMs', 'tokenBudget', 'executable', 'insideSandbox'];
export const DEFAULTS = { sandbox: 'read-only', addDirs: [], network: false, pluginRoots: [], model: null, effort: null,
  concurrency: 4, maxAgents: 1000, timeoutMs: 30 * 60 * 1000, tokenBudget: null, insideSandbox: false };

export function compile(source, filename = 'workflow.js') {
  if (!/^export const meta\s*=/m.test(source)) throw new RunnerError('CONFIG', `${filename} does not start a workflow with export const meta`);
  // Workflows are a literal meta export followed by a top-level body that uses
  // await and return, so they run as the body of an async function.
  return new vm.Script(`(async () => {\n${source.replace(/^export const meta\b/m, 'const meta')}\n})()`, { filename });
}

export function normalizeSettings(input) {
  for (const key of Object.keys(input)) if (!SETTINGS.includes(key)) throw new RunnerError('CONFIG', `Unknown setting: ${key}`);
  const settings = { ...DEFAULTS, ...input };
  if (!settings.script) throw new RunnerError('CONFIG', 'A workflow script is required');
  if (!BACKENDS.includes(settings.backend)) throw new RunnerError('CONFIG', `Unknown backend: ${settings.backend}`);
  if (!SANDBOXES.includes(settings.sandbox)) throw new RunnerError('CONFIG', `sandbox must be one of ${SANDBOXES.join(', ')}`);
  if (settings.network && settings.backend !== 'codex') throw new RunnerError('UNSUPPORTED', 'Network access is a Codex sandbox setting; other hosts use their own configuration');
  if (settings.network && settings.sandbox !== 'workspace-write') throw new RunnerError('CONFIG', '--network only applies to a workspace-write sandbox');
  if (settings.addDirs.length && settings.sandbox !== 'workspace-write') throw new RunnerError('CONFIG', '--add-dir only applies to a workspace-write sandbox');
  if (settings.insideSandbox && (settings.backend !== 'codex' || settings.sandbox !== 'workspace-write' || settings.addDirs.length)) {
    throw new RunnerError('CONFIG', 'Running inside the sandbox needs the codex backend, a workspace-write sandbox and no --add-dir');
  }
  for (const key of ['concurrency', 'maxAgents', 'timeoutMs']) {
    if (!Number.isSafeInteger(settings[key]) || settings[key] < 1) throw new RunnerError('CONFIG', `${key} must be a positive integer`);
  }
  if (settings.tokenBudget !== null && (!Number.isSafeInteger(settings.tokenBudget) || settings.tokenBudget < 1)) {
    throw new RunnerError('CONFIG', 'tokenBudget must be a positive integer');
  }
  return {
    ...settings,
    script: path.resolve(settings.script),
    cwd: path.resolve(settings.cwd ?? process.cwd()),
    addDirs: settings.addDirs.map(dir => path.resolve(dir)),
    pluginRoots: settings.pluginRoots.map(dir => path.resolve(dir)),
    executable: settings.executable ? path.resolve(settings.executable) : null,
  };
}

export const isInside = (child, parent) => child === parent || child.startsWith(parent + path.sep);

// agent() rejects with these, as the native tool does, so a script's own catch can fall
// back; they are also listed in the run's notes so an uncaught one is not silent.
const CALLER_ERRORS = new Set(['CONFIG', 'UNSUPPORTED', 'ROLE_NOT_FOUND', 'SCHEMA_CONFIG', 'PERMISSIONS']);

const slug = text => text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'agent';
// A pid alone can be reused after the runner dies, so a dead run could look alive. The
// start time and command name identify the runner.
// Returns undefined when ps cannot answer (under load it can time out), null when there
// is no such process.
export const processIdentity = pid => {
  if (!Number.isSafeInteger(pid) || pid < 1) return null;
  const result = spawnSync('/bin/ps', ['-p', String(pid), '-o', 'lstart=', '-o', 'comm='], { encoding: 'utf8', timeout: 5000 });
  if (result.error || result.signal) return undefined;
  return result.status === 0 && result.stdout.trim() ? result.stdout.trim() : null;
};
// When the identity cannot be checked (ps can time out, and the sandbox does not allow
// it), this falls back to the pid being alive.
export const isRunActive = (state, identify = processIdentity) => {
  if (!state.pid || !alive(state.pid)) return false;
  const current = state.processIdentity ? identify(state.pid) : undefined;
  return current === undefined || current === state.processIdentity;
};
export const alive = pid => {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
};

function preamble(registry) {
  return [
    // As Claude Code tells its workflow agents: the reply is data for the script.
    'Your final message is returned to the calling script as data, not shown to a person: give the answer itself.',
    // Translations Codex needs: workflow prompts name Claude Code tools, and there is no Skill tool.
    'Where the task names Claude Code tools (Read, Write, Edit, Grep, Glob, Bash, Skill), use the equivalent tools you have.',
    // Claude Code's own heading for its skill listing, which workflows check for by name
    // (code-improver's baseline looks for it before trusting a reviewer skill).
    'The following skills are available for use with the Skill tool. Here, use one by reading its file and following it:',
    ...[...registry.skills].map(([name, file]) => `- ${name}: ${file}`),
    'Agent types the task may name, with their definitions:',
    ...[...registry.agents].map(([name, entry]) => `- ${name}: ${entry.file}`),
  ].join('\n');
}

export async function runWorkflow(input, { resume = false, out, execute = executeWorker, log = () => {}, signal, env = process.env } = {}) {
  const settings = normalizeSettings(input);
  if (!out) throw new RunnerError('CONFIG', 'A run directory is required');
  out = path.resolve(out);
  // Workflow scripts run as trusted code with the runner's permissions: the user's, unless
  // it was launched inside the sandbox. Refuse one the audited target could have planted.
  const scriptPath = await realpath(settings.script);
  for (const root of [settings.cwd, ...settings.addDirs]) {
    const real = await realpath(root).catch(() => root);
    if (isInside(scriptPath, real)) {
      throw new RunnerError('CONFIG', `Refusing ${settings.script}: it is inside ${root}, which workers can write. Run workflows from an installed plugin`);
    }
  }
  const source = await readFile(settings.script, 'utf8');
  const script = compile(source, settings.script);
  const registry = await loadRegistry(settings.script, settings.pluginRoots);
  const here = path.dirname(fileURLToPath(import.meta.url));
  const runtime = await Promise.all(RUNTIME_FILES.map(file => readFile(path.join(here, file), 'utf8')));
  // Not the script source or the plugin definitions: as natively, a resume after an edit
  // replays up to the first agent call that changed. The executable is resolved afresh.
  const fingerprint = digest({ runtime, settings: { ...settings, executable: null } });
  const statePath = path.join(out, 'state.json');
  const lockPath = path.join(out, 'lock');

  let state;
  if (resume) {
    try { state = JSON.parse(await readFile(statePath, 'utf8')); }
    catch { throw new RunnerError('CONFIG', `No resumable run in ${out}`); }
    if (state.version !== STATE_VERSION) throw new RunnerError('CONFIG', 'Run was recorded by an incompatible runner version');
    if (state.status === 'completed') throw new RunnerError('CONFIG', 'Run already completed; start a new run to see changed files');
    if (state.fingerprint !== fingerprint) {
      throw new RunnerError('CONFIG', 'The runner or the run\'s settings changed since this run started; start a new run');
    }
  } else {
    // A run directory is never reused: mixing two runs' records would make
    // either one impossible to audit. A detached launch pre-creates it for its log.
    const existing = await readdir(out).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (existing && existing.some(name => name !== 'runner.log')) throw new RunnerError('CONFIG', `Run directory ${out} already exists; choose a new one`);
    await mkdir(out, { recursive: true, mode: 0o700 });
    await writeFile(path.join(out, 'workflow.js'), source, { mode: 0o600 });
    state = { version: STATE_VERSION, fingerprint, settings, status: 'running', startedAt: new Date().toISOString(),
      nextJob: 1, jobs: {}, usage: { outputTokens: 0, unknown: 0 }, notes: [] };
  }
  try { await writeFile(lockPath, String(process.pid), { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const holder = Number(await readFile(lockPath, 'utf8'));
    if (alive(holder)) throw new RunnerError('CONFIG', `Run is already active in process ${holder}`);
    await unlink(lockPath).catch(() => {});
    // A second resume racing for the same stale lock loses here rather than with a raw EEXIST.
    await writeFile(lockPath, String(process.pid), { flag: 'wx', mode: 0o600 }).catch(() => {
      throw new RunnerError('CONFIG', 'Another process is resuming this run');
    });
  }
  Object.assign(state, { status: 'running', pid: process.pid, processIdentity: processIdentity(process.pid), error: undefined, finishedAt: undefined });

  let saving = Promise.resolve();
  const save = () => {
    const content = JSON.stringify(state, null, 2);
    saving = saving.then(async () => {
      await writeFile(`${statePath}.tmp`, content, { mode: 0o600 });
      await rename(`${statePath}.tmp`, statePath);
    });
    return saving;
  };
  const note = message => {
    if (state.notes.includes(message)) return;
    state.notes.push(message);
    log(`Note: ${message}`);
  };

  const controller = new AbortController();
  let fatal;
  const fail = error => { fatal ??= error; controller.abort(error); };
  const interrupt = () => controller.abort(new RunnerError('INTERRUPTED', 'Run interrupted; continue it with --resume'));
  signal?.addEventListener('abort', interrupt, { once: true });
  if (signal?.aborted) interrupt();

  let active = 0;
  let calls = 0;
  let phase = '';
  const waiting = [];
  const pending = new Set();
  const occurrences = new Map();
  const acquire = async () => {
    if (active < settings.concurrency) { active++; return; }
    await new Promise(resolve => waiting.push(resolve));
  };
  const release = () => { const next = waiting.shift(); if (next) next(); else active--; };
  const total = settings.tokenBudget;
  const spent = () => state.usage.outputTokens;
  const remaining = () => total === null ? Infinity : Math.max(0, total - spent());
  const countUsage = tokens => {
    if (Number.isSafeInteger(tokens) && tokens >= 0) state.usage.outputTokens += tokens;
    else {
      // Usually a worker that timed out or crashed. Stopping every later agent over it
      // would turn one failure into silent coverage loss, so the budget counts what is known.
      state.usage.unknown++;
      if (total !== null) note('Some workers reported no token usage; the budget counts only reported tokens.');
    }
  };
  const baseEnv = { ...env };
  const readDirs = registry.roots.filter(root => root !== settings.cwd && !root.startsWith(settings.cwd + path.sep));
  // Only Codex confines worker commands to an OS sandbox, and only a run that may
  // write gets the tool caches; a read-only run stays read-only.
  let cacheDirs = [];
  let codexHome;
  let toolEnv;
  if (settings.insideSandbox) {
    codexHome = await prepareCodexHome(path.join(out, 'codex-home'), baseEnv);
    toolEnv = toolCacheEnv(path.join(baseEnv.TMPDIR ?? os.tmpdir(), 'workflow-runner-cache'));
    note("Workers run inside this session's sandbox, so its rules apply to every role.");
  } else if (settings.backend === 'codex' && settings.sandbox === 'workspace-write') {
    const ownFiles = [...registry.skills.values(), ...[...registry.agents.values()].map(entry => entry.file)]
      .filter(file => isInside(file, registry.owner));
    const pluginText = [source, ...await Promise.all(ownFiles.map(file => readFile(file, 'utf8')))].join('\n');
    cacheDirs = toolCaches(baseEnv, pluginText);
  }
  if (cacheDirs.length) note(`Workers may write these tool caches: ${cacheDirs.join(', ')}`);
  // Inside Codex's macOS sandbox, Semgrep cannot read the keychain's trust anchors and
  // crashes ("ca-certs: empty trust anchors"); the system bundle is the same trust store.
  const certFile = settings.backend === 'codex' && settings.sandbox !== 'danger-full-access' && process.platform === 'darwin'
    && !baseEnv.SSL_CERT_FILE && existsSync('/etc/ssl/cert.pem') ? '/etc/ssl/cert.pem' : undefined;
  // Claude Code's resume rule: replay recorded agents until the first one that changed
  // or failed, then run that one and every agent after it live.
  let diverged = !resume;

  const dispatch = async (prompt, rawOptions) => {
    if (controller.signal.aborted) {
      // Yield a macrotask first: a script that keeps calling agent() in a loop
      // after an abort must not starve the event loop that would end the run.
      await new Promise(resolve => setImmediate(resolve));
      throw controller.signal.reason;
    }
    if (typeof prompt !== 'string' || !prompt.trim()) throw new RunnerError('CONFIG', 'agent() needs a non-empty prompt');
    if (rawOptions === null || typeof rawOptions !== 'object' || Array.isArray(rawOptions)) throw new RunnerError('CONFIG', 'agent() options must be an object');
    // Options built inside the VM become plain host values before validation.
    const options = structuredClone(rawOptions);
    for (const key of Object.keys(options)) {
      if (!OPTIONS.has(key)) throw new RunnerError('UNSUPPORTED', `agent() option ${key} is not supported by workflow-runner`);
    }
    if (options.schema !== undefined) checkSchema(options.schema);
    const role = resolveRole(registry, options.agentType);
    if (roleWrites(role) && settings.sandbox === 'read-only') {
      throw new RunnerError('PERMISSIONS', `${role.name} writes files, but the launching session's sandbox is read-only`);
    }
    // A role that can neither write nor run commands is confined to read-only
    // whatever the run allows. The host sandbox enforces it; tool lists are
    // otherwise advisory outside Claude Code.
    const sandbox = settings.sandbox !== 'read-only' && (!role || roleWrites(role) || roleRunsCommands(role)) ? settings.sandbox : 'read-only';
    const model = resolveModel(settings.backend, { override: settings.model, requested: options.model ?? role?.model });
    const effort = resolveEffort(settings.backend, { override: settings.effort, requested: options.effort });
    if (model.note) note(model.note);
    if (effort.note) note(effort.note);
    if (++calls > settings.maxAgents) throw new RunnerError('DISPATCH_LIMIT', `Workflow exceeded ${settings.maxAgents} agent calls (--max-agents)`);

    const identity = digest({ prompt, schema: options.schema, agentType: options.agentType, role: role?.hash, model: model.model, effort: effort.effort, sandbox });
    const occurrence = (occurrences.get(identity) ?? 0) + 1;
    occurrences.set(identity, occurrence);
    const key = `${identity.slice(0, 16)}-${occurrence}`;
    const label = options.label ?? '';
    const previous = state.jobs[key];
    if (previous?.status === 'completed' && !diverged) {
      const saved = JSON.parse(await readFile(path.join(previous.dir, 'result.json'), 'utf8'));
      if (digest(saved) !== previous.resultHash) throw new RunnerError('CONFIG', `Recorded result for ${previous.dir} was modified; start a new run`);
      log(`Replay ${label || key}`);
      return saved.value;
    }
    diverged = true;
    if (total !== null && remaining() <= 0) throw new RunnerError('BUDGET', 'Token budget exhausted');

    await acquire();
    try {
      controller.signal.throwIfAborted();
      // Checked again: calls queued for a slot passed the first check before anything was spent.
      if (total !== null && remaining() <= 0) throw new RunnerError('BUDGET', 'Token budget exhausted');
      const seq = state.nextJob++;
      const dir = path.join(out, 'jobs', `${String(seq).padStart(4, '0')}-${slug(label)}`);
      await mkdir(dir, { recursive: true, mode: 0o700 });
      const job = { key, seq, label, phase: options.phase ?? phase, role: role?.name ?? null, model: model.model ?? null,
        effort: effort.effort ?? null, sandbox, attempts: (previous?.attempts ?? 0) + 1, dir, status: 'running' };
      state.jobs[key] = job;
      await writeFile(path.join(dir, 'job.json'), JSON.stringify({ ...job, task: prompt }, null, 2), { mode: 0o600 });
      await save();
      log(`Start ${label || key}${role ? ` [${role.name}]` : ''}`);
      const pluginRoot = role?.root ?? registry.owner;
      const roleText = role
        ? `You are acting as the ${role.name} agent, defined in ${role.file}.${role.tools ? ` Use only these kinds of operation: ${role.tools.join(', ')}.` : ''} Its instructions follow.\n\n${role.body.trim()}`
        : '';
      let reply;
      try {
        reply = await execute({
          backend: settings.backend, cwd: settings.cwd, directory: dir, schema: options.schema, tools: role?.tools,
          prompt: [preamble(registry), roleText, `Task:\n${prompt}`].filter(Boolean).join('\n\n'),
          sandbox, insideSandbox: settings.insideSandbox, toolEnv, addDirs: settings.addDirs, cacheDirs, readDirs, certFile,
          model: model.model, effort: effort.effort,
          // Never for a role without a shell: on Claude Code it could not reach the network.
          network: settings.network && roleRunsCommands(role),
          env: { ...baseEnv, CLAUDE_PLUGIN_ROOT: pluginRoot, CODEX_PLUGIN_ROOT: pluginRoot, ...(codexHome ? { CODEX_HOME: codexHome } : {}) },
        }, { executable: settings.executable ?? settings.backend, timeoutMs: settings.timeoutMs, signal: controller.signal });
        if (!reply || reply.value === undefined) throw new RunnerError('PROTOCOL', 'Worker returned no value');
        if (options.schema) validate(reply.value, options.schema);
      } catch (error) {
        countUsage(error.outputTokens ?? reply?.outputTokens);
        Object.assign(job, { status: 'failed', error: { code: error.code ?? 'ERROR', message: error.message } });
        await writeFile(path.join(dir, 'error.json'), JSON.stringify({ ...job.error, diagnostics: error.diagnostics }, null, 2), { mode: 0o600 });
        await save();
        if (controller.signal.aborted) throw controller.signal.reason;
        if (!isWorkerFailure(error)) throw error;
        // As under the native Workflow tool, a failed worker is a null result.
        log(`Failed ${label || key}: ${error.message}`);
        return null;
      }
      countUsage(reply.outputTokens);
      const saved = { value: reply.value };
      await writeFile(path.join(dir, 'result.json'), JSON.stringify(saved, null, 2), { mode: 0o600 });
      Object.assign(job, { status: 'completed', outputTokens: reply.outputTokens ?? null, sessionId: reply.sessionId ?? null,
        resultHash: digest(saved) });
      if (reply.diagnostics?.length) job.diagnostics = reply.diagnostics;
      await save();
      log(`Done ${label || key}`);
      return reply.value;
    } finally { release(); }
  };

  const agent = (prompt, options = {}) => {
    const promise = dispatch(prompt, options).catch(error => {
      if (CALLER_ERRORS.has(error.code) || error.code === 'BUDGET') note(`agent() rejected: ${error.message}`);
      // The dispatch cap is a runaway backstop, and anything else is a runner fault: both end the run.
      else if (error.code !== 'BUDGET' && !controller.signal.aborted) fail(error);
      throw error;
    });
    pending.add(promise);
    promise.then(() => pending.delete(promise), () => pending.delete(promise));
    return promise;
  };
  const parallel = async thunks => {
    if (!Array.isArray(thunks) || thunks.some(thunk => typeof thunk !== 'function')) throw new RunnerError('CONFIG', 'parallel() expects an array of functions');
    if (thunks.length > MAX_ITEMS) throw new RunnerError('CONFIG', `parallel() accepts at most ${MAX_ITEMS} items`);
    return Promise.all(thunks.map(async thunk => {
      try { return await thunk(); }
      catch (error) {
        // Recorded as a note, not only logged: a skipped branch is missing coverage.
        note(`Branch failed: ${error?.message ?? String(error)}`);
        await save();
        return null;
      }
    }));
  };
  const pipeline = (items, ...stages) => {
    if (!Array.isArray(items) || !stages.length || stages.some(stage => typeof stage !== 'function')) {
      throw new RunnerError('CONFIG', 'pipeline() expects an array and one or more stage functions');
    }
    return parallel(items.map((item, index) => async () => {
      let value = item;
      for (const stage of stages) value = await stage(value, item, index);
      return value;
    }));
  };

  let failure;
  try {
    await save();
    const context = vm.createContext({
      args: structuredClone(settings.args), agent, parallel, pipeline,
      phase: title => { phase = String(title); log(`Phase: ${phase}`); },
      log: message => log(String(message)),
      budget: Object.freeze({ total, spent, remaining }),
      workflow: () => { throw new RunnerError('UNSUPPORTED', 'Nested workflow() calls are not supported; run the other workflow separately'); },
    }, { codeGeneration: { strings: false, wasm: false } });
    // Same rule as the native tool: these would make a resumed run diverge.
    vm.runInContext(`Math.random = () => { throw new Error('Math.random() is unavailable in workflows; vary prompts by index instead') };
      Date = class extends Date {
        constructor(...a) { if (!a.length) throw new Error('new Date() is unavailable in workflows; pass timestamps through args'); super(...a) }
        static now() { throw new Error('Date.now() is unavailable in workflows; pass timestamps through args') }
      };`, context);
    let onAbort;
    const aborted = new Promise((_, reject) => { onAbort = () => reject(controller.signal.reason); });
    // The finally block aborts after a normal finish too; nothing awaits that.
    aborted.catch(() => {});
    controller.signal.addEventListener('abort', onAbort, { once: true });
    if (controller.signal.aborted) onAbort();
    // Cloned into this realm: the summary and result.json carry plain data, not VM objects.
    const returned = await Promise.race([script.runInContext(context, { timeout: 1000 }), aborted]);
    let value;
    try { value = structuredClone(returned); }
    catch (error) { throw new RunnerError('NO_RESULT', `Workflow returned a value that is not plain data: ${error.message}`); }
    if (fatal) throw fatal;
    if (pending.size) throw new RunnerError('UNAWAITED', 'Workflow returned before all of its agent() calls finished');
    // A workflow may legitimately stop before dispatching (insecure-defaults reports a
    // missing plugin root that way). Its own value says why; the note keeps it visible.
    if (!calls) note('The workflow made no agent() calls.');
    if (value === undefined) throw new RunnerError('NO_RESULT', 'Workflow returned no result');
    // Natively a run whose agents all failed still completes; say so loudly, because an
    // expired login or a broken CLI looks exactly like a workflow that found nothing.
    const attempted = Object.values(state.jobs);
    if (attempted.length && attempted.every(job => job.status === 'failed')) {
      note(`Every agent failed, so this result reflects no completed work. First error: ${attempted[0].error?.message}`);
    }
    await writeFile(path.join(out, 'result.json'), JSON.stringify(value, null, 2), { mode: 0o600 });
    state.status = 'completed';
    return summarize(state, out, value);
  } catch (thrown) {
    // A script can throw anything; errors from the VM realm also fail instanceof Error.
    const error = thrown !== null && typeof thrown === 'object' ? thrown : new RunnerError('SCRIPT', `Workflow threw ${String(thrown)}`);
    failure = error;
    state.status = error.code === 'INTERRUPTED' ? 'interrupted' : 'failed';
    state.error = { code: error.code ?? 'ERROR', message: error.message };
    throw Object.assign(error, { runDir: out, summary: summarize(state, out) });
  } finally {
    controller.abort(failure ?? new RunnerError('FINISHED', 'Run finished'));
    await Promise.allSettled([...pending]);
    signal?.removeEventListener('abort', interrupt);
    // Only links and the workers' own logs; a resume makes a new one.
    if (codexHome) await rm(codexHome, { recursive: true, force: true }).catch(() => {});
    state.finishedAt = new Date().toISOString();
    delete state.pid;
    await save();
    await unlink(lockPath).catch(() => {});
  }
}

export function summarize(state, runDir, result) {
  const jobs = Object.values(state.jobs);
  return {
    status: state.status,
    runDir,
    ...(result === undefined ? {} : { result }),
    ...(state.error ? { error: state.error } : {}),
    agents: { completed: jobs.filter(job => job.status === 'completed').length, failed: jobs.filter(job => job.status === 'failed').length },
    workerFailures: jobs.filter(job => job.status === 'failed').map(job => ({ label: job.label, dir: job.dir, error: job.error })),
    outputTokens: state.usage.outputTokens,
    ...(state.usage.unknown ? { workersWithoutUsage: state.usage.unknown } : {}),
    notes: state.notes,
  };
}
