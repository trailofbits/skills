#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, existsSync, openSync } from 'node:fs';
import { readFile, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, isInside, isRunActive, processIdentity, runWorkflow, summarize } from './runtime.mjs';
import { loadRegistry } from './definitions.mjs';
import { detectBackend, findExecutable, prepareCodexHome } from './backends.mjs';
import { killPending } from './process.mjs';
import { RunnerError } from './errors.mjs';

const USAGE = `Usage:
  node run.mjs WORKFLOW.js [options]                     run a workflow
  node run.mjs --resume RUN_DIR [--detach]                continue an interrupted run (pass --executable
                                                          again if the first launch used one)
  node run.mjs --status RUN_DIR                           report a run's progress or result
  node run.mjs --cancel RUN_DIR                           stop a running run; it can be resumed
  node run.mjs --check WORKFLOW.js                        compile only; starts nothing

Inside Codex's sandbox the runner and its workers run there, if the sandbox allows
network access; otherwise it exits with NEEDS_ESCALATION, and the same command must be
run again with escalated permissions. --resume and --cancel run the way the launch did.

Options:
  --out NEW_RUN_DIR    run directory (default: workflow-runs/<workflow>-<time> under the
                       temp directory inside the sandbox, else under ~/.codex)
  --args-file FILE     JSON value the workflow receives as \`args\`
  --args JSON          the same, inline
  --cwd DIR            directory workers run in (default: current directory)
  --backend NAME       codex or gemini (default: the host this runs inside)
  --sandbox MODE       the launching session's sandbox: read-only (default), workspace-write,
                       or danger-full-access. Workers run in the same mode
  --add-dir DIR        another directory workers may write; repeatable, workspace-write only
  --network            let Codex workers' commands reach the network; workspace-write only
  --plugin-root DIR    installed plugin whose agents or skills the workflow uses; repeatable
  --model MODEL        model for every worker, replacing the workflow's choices
  --effort LEVEL       effort for every worker: low, medium, high, xhigh, max
  --concurrency N      workers at once (default 4)
  --max-agents N       agent() calls allowed in the run (default 1000)
  --timeout-ms N       per-worker timeout (default 1800000)
  --token-budget N     output-token budget, exposed to the workflow as budget.total
  --executable PATH    backend CLI to launch (default: the backend's name on PATH)
  --detach             start in the background, print the run directory, and return`;

const OPTIONS = {
  help: { type: 'boolean' }, check: { type: 'boolean' }, detach: { type: 'boolean' }, network: { type: 'boolean' },
  status: { type: 'string' }, cancel: { type: 'string' }, resume: { type: 'string' }, out: { type: 'string' }, cwd: { type: 'string' },
  'args-file': { type: 'string' }, args: { type: 'string' }, backend: { type: 'string' }, sandbox: { type: 'string' },
  'add-dir': { type: 'string', multiple: true }, 'plugin-root': { type: 'string', multiple: true },
  model: { type: 'string' }, effort: { type: 'string' }, concurrency: { type: 'string' }, 'max-agents': { type: 'string' },
  'timeout-ms': { type: 'string' }, 'token-budget': { type: 'string' }, executable: { type: 'string' },
};
const self = fileURLToPath(import.meta.url);
// Resolves once written: the process exits right after, and pipes are asynchronous on macOS.
const print = value => new Promise(resolve => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`, resolve));
const integer = (values, key) => {
  if (values[key] === undefined) return undefined;
  const value = Number(values[key]);
  if (!Number.isSafeInteger(value) || value < 1) throw new RunnerError('CONFIG', `--${key} must be a positive integer`);
  return value;
};
const readState = async runDir => {
  try { return JSON.parse(await readFile(path.join(runDir, 'state.json'), 'utf8')); }
  catch { throw new RunnerError('CONFIG', `No run recorded in ${runDir}`); }
};

async function settingsFrom(values, positionals) {
  if (positionals.length !== 1) throw new RunnerError('CONFIG', 'Pass exactly one workflow script; see --help');
  if (values['args-file'] && values.args) throw new RunnerError('CONFIG', 'Use --args-file or --args, not both');
  let args;
  try {
    if (values['args-file']) args = JSON.parse(await readFile(values['args-file'], 'utf8'));
    else if (values.args !== undefined) args = JSON.parse(values.args);
  } catch (error) { throw new RunnerError('CONFIG', `Workflow arguments are not valid JSON: ${error.message}`); }
  const settings = {
    script: path.resolve(positionals[0]), args, cwd: path.resolve(values.cwd ?? process.cwd()),
    backend: values.backend ?? detectBackend(process.env), sandbox: values.sandbox, network: values.network,
    addDirs: values['add-dir'], pluginRoots: values['plugin-root'], model: values.model, effort: values.effort,
    concurrency: integer(values, 'concurrency'), maxAgents: integer(values, 'max-agents'),
    timeoutMs: integer(values, 'timeout-ms'), tokenBudget: integer(values, 'token-budget'),
    executable: values.executable && path.resolve(values.executable),
  };
  return Object.fromEntries(Object.entries(settings).filter(([, value]) => value !== undefined));
}

// In a workspace-write run, workers can write the target, temp and any --add-dir. Run
// records there could be rewritten by a prompt-injected worker and then trusted by an
// escalated --resume, so the records must live where workers cannot write.
async function assertPrivateRunDir(runDir, settings) {
  if ((settings.sandbox ?? 'read-only') !== 'workspace-write') return;
  const real = async dir => realpath(dir).catch(() => dir);
  let existing = runDir;
  while (!(await realpath(existing).then(() => true, () => false))) existing = path.dirname(existing);
  const target = path.join(await real(existing), path.relative(existing, runDir));
  const roots = [settings.cwd ?? process.cwd(), ...(settings.addDirs ?? []), os.tmpdir(), '/tmp', process.env.TMPDIR].filter(Boolean);
  for (const root of roots) {
    if (isInside(target, await real(path.resolve(root)))) {
      throw new RunnerError('CONFIG', `Run directory ${runDir} is inside ${root}, which workers can write; use one such as ~/.codex/workflow-runs/<name>`);
    }
  }
}

const CANCEL_FILE = 'cancel';
const codexHome = () => process.env.CODEX_HOME ?? path.join(os.homedir(), '.codex');

function defaultRunDir(script, inside) {
  const now = new Date();
  const two = n => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${two(now.getMonth() + 1)}${two(now.getDate())}-${two(now.getHours())}${two(now.getMinutes())}${two(now.getSeconds())}`;
  const root = inside ? path.join(os.tmpdir(), 'workflow-runs') : path.join(codexHome(), 'workflow-runs');
  return path.join(root, `${path.basename(script, '.js')}-${stamp}`);
}

// Inside the session's sandbox, workers run there too, with a Codex folder of their own.
// They still need to reach the model, and somewhere to write; without either, the launch
// has to be repeated with escalated permissions.
function assertCanRunInside(settings) {
  const escalate = reason => new RunnerError('NEEDS_ESCALATION', `${reason}. Run the same command again with escalated permissions`);
  if (process.env.CODEX_SANDBOX_NETWORK_DISABLED) throw escalate('This sandbox has no network access, which workers need to reach the model');
  if ((settings.backend ?? 'codex') !== 'codex') throw new RunnerError('CONFIG', 'Inside Codex, use the codex backend');
  if (settings.sandbox !== 'workspace-write') throw escalate(`Workers cannot start inside a ${settings.sandbox ?? 'read-only'} sandbox`);
  if (settings.addDirs?.length) throw escalate('--add-dir grants access beyond this sandbox');
}

async function status(runDir) {
  let state = await readState(runDir);
  let stopped = false;
  if (state.status === 'running' && !isRunActive(state)) {
    // Read again: a run that finished between the first read and the check is not stopped.
    state = await readState(runDir);
    stopped = state.status === 'running';
  }
  let result;
  if (state.status === 'completed') result = JSON.parse(await readFile(path.join(runDir, 'result.json'), 'utf8'));
  let log = [];
  try { log = (await readFile(path.join(runDir, 'runner.log'), 'utf8')).trimEnd().split('\n').slice(-15); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const jobs = Object.values(state.jobs);
  const running = jobs.filter(job => job.status === 'running').map(job => job.label || job.key);
  const report = { ...summarize(state, runDir, result), status: stopped ? 'stopped' : state.status,
    ...(state.status === 'running' && !stopped ? { pid: state.pid } : {}), running, log };
  if (stopped || state.status === 'interrupted') report.next = `Continue with: node ${self} --resume ${runDir}`;
  // One readable line, printed last: Codex shows only the tail of a command's output.
  const minutes = Math.round((Date.parse(state.finishedAt ?? new Date().toISOString()) - Date.parse(state.startedAt)) / 60_000);
  const phase = jobs.at(-1)?.phase;
  const shown = running.slice(0, 3).join(', ') + (running.length > 3 ? ', …' : '');
  report.progress = [report.status, phase && `phase ${phase}`,
    `${report.agents.completed} done, ${running.length} running${running.length ? ` (${shown})` : ''}, ${report.agents.failed} failed`,
    `${minutes}m elapsed`].filter(Boolean).join(' · ');
  await print(report);
  await new Promise(resolve => process.stderr.write(`progress: ${report.progress}\n`, resolve));
  return state.status === 'failed' || stopped ? 1 : 0;
}

// A request file rather than a signal: the runner checks for it, stops its workers and
// records the run as interrupted. Nothing is ever sent to a pid that may have been
// reused, and it works inside the sandbox, where the runner's identity cannot be checked.
export async function cancel(runDir, { timeoutMs = 15_000, pollMs = 200, identify = processIdentity } = {}) {
  const state = await readState(runDir);
  if (state.status === 'running' && isRunActive(state, identify)) {
    await writeFile(path.join(runDir, CANCEL_FILE), '', { mode: 0o600 });
    for (let waited = 0; waited < timeoutMs && (await readState(runDir)).status === 'running'; waited += pollMs) {
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
  }
  const after = await readState(runDir);
  if (after.status === 'running' && isRunActive(after, identify)) {
    throw new RunnerError('CANCEL_TIMEOUT', `Runner did not stop within ${timeoutMs} ms; cancellation is incomplete`);
  }
  return status(runDir);
}

// No model calls: the CLI must accept every flag the runner passes, and be logged in.
// Without this, a renamed flag or an expired login turns every worker into a null result.
async function preflight(settings) {
  if (settings.backend !== 'codex') return;
  if (settings.insideSandbox) {
    const home = await prepareCodexHome(await mkdtemp(path.join(os.tmpdir(), 'workflow-runner-preflight-')), process.env);
    try { return checkCli(settings, { ...process.env, CODEX_HOME: home }); }
    finally { await rm(home, { recursive: true, force: true }); }
  }
  return checkCli(settings, process.env);
}

function checkCli(settings, env) {
  const executable = findExecutable(settings.executable ?? 'codex', env);
  if (!executable) throw new RunnerError('LAUNCH', `${settings.executable ?? 'codex'} not found on PATH`);
  const help = spawnSync(executable, ['exec', '--help'], { encoding: 'utf8', timeout: 20_000, env });
  const missing = ['--json', '--ephemeral', '--skip-git-repo-check', '--cd', '--sandbox', '--add-dir', '--disable', '--output-schema', '--output-last-message']
    .filter(flag => !(help.stdout ?? '').includes(flag));
  if (help.status !== 0 || missing.length) {
    throw new RunnerError('LAUNCH', `This Codex CLI does not support ${missing.join(', ') || '`codex exec --help`'}; the runner was tested with Codex 0.163`);
  }
  const login = spawnSync(executable, ['login', 'status'], { encoding: 'utf8', timeout: 20_000, env });
  if (login.status !== 0) throw new RunnerError('LAUNCH', `Codex is not logged in: ${(login.stdout + login.stderr).trim()}`);
}

// Re-launches this command without --detach, logging to RUN_DIR/runner.log, and
// returns once the run has recorded its start, so a setup error is still seen.
export async function detach(argv, runDir, resuming, { spawnRunner = spawn, timeoutMs = 30_000, pollMs = 100 } = {}) {
  if (!resuming) {
    const existing = await readdir(runDir).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (existing) throw new RunnerError('CONFIG', `Run directory ${runDir} already exists; choose a new one`);
    await mkdir(runDir, { recursive: true, mode: 0o700 });
  }
  const before = resuming ? (await readState(runDir)).finishedAt : undefined;
  const fd = openSync(path.join(runDir, 'runner.log'), 'a', 0o600);
  // Only progress goes to the log; --status reads the summary from state.json.
  const child = spawnRunner(process.execPath, [self, ...argv.filter(arg => arg !== '--detach')], { detached: true, stdio: ['ignore', 'ignore', fd] });
  closeSync(fd);
  child.unref();
  let exited = false;
  let exitReason;
  let acknowledged = false;
  child.on('exit', (code, signal) => { exited = true; exitReason = signal ?? code; });
  child.on('error', error => { exited = true; exitReason = error.message; });
  for (let waited = 0; waited < timeoutMs; waited += pollMs) {
    await new Promise(resolve => setTimeout(resolve, pollMs));
    const state = await readFile(path.join(runDir, 'state.json'), 'utf8').then(JSON.parse, () => null);
    if (state && (state.pid === child.pid || (exited && state.finishedAt !== before))) { acknowledged = true; break; }
    if (exited) {
      const log = await readFile(path.join(runDir, 'runner.log'), 'utf8');
      throw new RunnerError('CONFIG', `Runner exited before starting (${exitReason}):\n${log.trim().split('\n').slice(-10).join('\n')}`);
    }
  }
  // Never report "started" for a run that did not record its start.
  if (!acknowledged) {
    child.kill('SIGTERM');
    throw new RunnerError('STARTUP_TIMEOUT', `Runner did not acknowledge startup within ${timeoutMs} ms; inspect ${path.join(runDir, 'runner.log')}`);
  }
  await print({ status: 'started', runDir, pid: child.pid, log: path.join(runDir, 'runner.log'),
    next: `Check progress with: node ${self} --status ${runDir}` });
  return 0;
}

export async function main(argv = process.argv.slice(2)) {
  const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  if (values.help) { console.log(USAGE); return 0; }
  if (values.status) return status(path.resolve(values.status));
  if (values.cancel) return cancel(path.resolve(values.cancel));
  if (values.check) {
    if (positionals.length !== 1) throw new RunnerError('CONFIG', 'Pass exactly one workflow script to --check');
    const script = path.resolve(positionals[0]);
    compile(await readFile(script, 'utf8'), script);
    const registry = await loadRegistry(script, (values['plugin-root'] ?? []).map(root => path.resolve(root)));
    await print({ status: 'compiled', script, plugin: registry.owner, agents: [...registry.agents.keys()] });
    return 0;
  }
  // CODEX_SANDBOX is set only inside the sandbox. Not CODEX_SANDBOX_NETWORK_DISABLED: Codex
  // sets that on escalated commands too, since it reflects the network policy, not the sandbox.
  const inside = Boolean(process.env.CODEX_SANDBOX);
  let settings;
  let runDir;
  if (values.resume) {
    const extra = Object.keys(values).filter(key => !['resume', 'detach', 'executable'].includes(key));
    if (extra.length || positionals.length) throw new RunnerError('CONFIG', '--resume takes only a run directory (and --detach, --executable); the original settings are reused');
    runDir = path.resolve(values.resume);
    settings = { ...(await readState(runDir)).settings };
    // Never launch a program named by the run records: resolve it again.
    if (values.executable) settings.executable = path.resolve(values.executable);
    else delete settings.executable;
    // Records written inside the sandbox could have been changed by any command there, so
    // an escalated resume must not trust them; and the sandbox cannot write the others.
    if (Boolean(settings.insideSandbox) !== inside) {
      throw settings.insideSandbox
        ? new RunnerError('CONFIG', 'This run was launched inside the sandbox; resume it there, without escalated permissions')
        : new RunnerError('NEEDS_ESCALATION', 'This run was launched with escalated permissions; resume it the same way');
    }
  } else {
    settings = await settingsFrom(values, positionals);
    if (inside) settings.insideSandbox = true;
    runDir = path.resolve(values.out ?? defaultRunDir(settings.script, inside));
  }
  if (inside) assertCanRunInside(settings);
  else await assertPrivateRunDir(runDir, settings);
  await preflight(settings);
  // The detached runner must use this run directory, not pick its own.
  if (values.detach) return detach(values.out || values.resume ? argv : [...argv, '--out', runDir], runDir, Boolean(values.resume));

  const controller = new AbortController();
  const stop = () => {
    if (controller.signal.aborted) { killPending(); process.exit(130); }
    process.stderr.write('Stopping workers; interrupt again to exit immediately\n');
    controller.abort();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  const cancelFile = path.join(runDir, CANCEL_FILE);
  await rm(cancelFile, { force: true });
  const watch = setInterval(() => { if (!controller.signal.aborted && existsSync(cancelFile)) stop(); }, 500);
  watch.unref();
  try {
    await print(await runWorkflow(settings, { resume: Boolean(values.resume), out: runDir, signal: controller.signal,
      log: message => process.stderr.write(`${message}\n`) }));
    return 0;
  } catch (error) {
    if (error.summary) await print(error.summary);
    throw error;
  } finally {
    clearInterval(watch);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  // Exit explicitly: a workflow loop still spinning after a failure must not keep the process alive.
  // killPending first: exiting drops the timers that would SIGKILL a worker's leftovers.
  main().then(code => { killPending(); process.exit(code); }, error => {
    killPending();
    process.stderr.write(`${error instanceof RunnerError ? `${error.code}: ${error.message}` : error.stack}\n`, () => process.exit(1));
  });
}
