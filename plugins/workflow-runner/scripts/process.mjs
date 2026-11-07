import { spawn } from 'node:child_process';
import { RunnerError } from './errors.mjs';

const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
// After a worker exits, commands it left in the background can hold its pipes
// open indefinitely. Give them this long to flush, then stop waiting.
const DRAIN_MS = 2000;
const KILL_GRACE_MS = 2000;

// Workers sent SIGTERM whose SIGKILL is still due. Kept outside any one call: a
// worker's promise settles once its output closes, and a child that ignores
// SIGTERM can still be running then. It gets the SIGKILL regardless.
const pendingKills = new Map();

// For a runner about to exit, whose timers would never fire: kill now.
export function killPending() {
  for (const { timer, kill } of pendingKills.values()) { clearTimeout(timer); kill(); }
  pendingKills.clear();
}

// Runs one worker CLI. On POSIX the worker leads its own process group, so a
// timeout or cancellation also stops the commands it started. On Windows only
// the direct child is signalled.
export function runProcess(command, args, { cwd, env, input = '', timeoutMs, signal }) {
  return new Promise((resolve, reject) => {
    const grouped = process.platform !== 'win32';
    const stdout = [];
    const stderr = [];
    const timers = [];
    let bytes = 0;
    let failure = null;
    let exit = null;
    let settled = false;
    let child;

    const later = (ms, fn) => { const timer = setTimeout(fn, ms); timers.push(timer); };
    const signalWorker = name => {
      if (!child?.pid) return;
      try { grouped ? process.kill(-child.pid, name) : child.kill(name); }
      catch (error) { if (error.code !== 'ESRCH') failure ??= new RunnerError('EXIT', `Cannot signal worker: ${error.message}`); }
    };
    const terminate = () => {
      signalWorker('SIGTERM');
      const pid = child?.pid;
      if (!pid || pendingKills.has(pid)) return;
      const kill = () => signalWorker('SIGKILL');
      pendingKills.set(pid, { kill, timer: setTimeout(() => { pendingKills.delete(pid); kill(); }, KILL_GRACE_MS) });
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      signal?.removeEventListener('abort', onAbort);
      for (const stream of [child?.stdin, child?.stdout, child?.stderr]) stream?.destroy();
      const details = {
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        exitCode: exit?.code ?? null,
      };
      if (failure) reject(Object.assign(failure, details));
      else if (exit?.code !== 0) {
        const tail = details.stderr.trim().split('\n').slice(-5).join('\n');
        reject(new RunnerError('EXIT', `${command} exited with ${exit?.code ?? exit?.signal}${tail ? `: ${tail}` : ''}`, details));
      } else resolve(details);
    };
    const fail = error => {
      failure ??= error;
      terminate();
      // A worker that ignores SIGKILL (uninterruptible I/O) must not hang the run.
      later(KILL_GRACE_MS + DRAIN_MS + 1000, finish);
    };
    const onAbort = () => fail(new RunnerError('ABORTED', 'Worker cancelled'));

    try {
      child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], detached: grouped });
    } catch (error) {
      reject(new RunnerError('LAUNCH', `Cannot start ${command}: ${error.message}`));
      return;
    }
    later(timeoutMs, () => fail(new RunnerError('TIMEOUT', `Worker exceeded ${timeoutMs} ms`)));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();

    const collect = chunks => chunk => {
      if (bytes > MAX_OUTPUT_BYTES) return; // already stopping; one signal is enough
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) fail(new RunnerError('OUTPUT_LIMIT', `Worker output exceeded ${MAX_OUTPUT_BYTES} bytes`));
      else chunks.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') failure ??= new RunnerError('LAUNCH', `Cannot write worker input: ${error.message}`); });
    child.on('error', error => {
      failure ??= new RunnerError('LAUNCH', `Cannot start ${command}: ${error.message}`);
      if (!child.pid) finish();
      else fail(failure);
    });
    child.on('exit', (code, name) => {
      exit = { code, signal: name };
      // Reap anything the worker left behind; ESRCH means there was nothing.
      terminate();
      later(DRAIN_MS, finish);
    });
    child.on('close', finish);
    child.stdin.end(input);
  });
}
