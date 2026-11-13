import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { promisify } from 'node:util';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { isRunActive, runWorkflow } from '../scripts/runtime.mjs';
import { cancel, detach } from '../scripts/run.mjs';
import { RunnerError } from '../scripts/errors.mjs';
import { fakeCli, fixture, readJson, readLog, reply, runner, taskOf } from './helpers.mjs';

const exec = promisify(execFile);
const cli = async (args, env = {}) => {
  try {
    const { stdout, stderr } = await exec(process.execPath, [runner, ...args], { env: { ...process.env, ...env } });
    return { code: 0, stdout, stderr, json: JSON.parse(stdout) };
  } catch (error) {
    let json;
    try { json = JSON.parse(error.stdout); } catch { json = null; }
    return { code: error.code, stdout: error.stdout, stderr: error.stderr, json };
  }
};
const WORKFLOW = `phase('Ask')
const answers = await parallel(args.items.map(item => () => agent('echo ' + item, { label: 'ask-' + item })))
return { answers }`;

test('a foreground run prints its summary and records every worker', async t => {
  const f = await fixture(t, WORKFLOW);
  const run = await cli([f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli,
    '--args', '{"items":["a","b"]}'], { FAKE_CLI_LOG: f.log });
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(run.json.result, { answers: ['a', 'b'] });
  assert.deepEqual(run.json.agents, { completed: 2, failed: 0 });
  assert.match(run.stderr, /Phase: Ask/);
  const [first] = await readLog(f.log);
  assert.equal(first.argv[first.argv.indexOf('--sandbox') + 1], 'read-only', 'read-only is the default');
  assert.deepEqual(await readJson(path.join(f.out, 'result.json')), { answers: ['a', 'b'] });

  const status = await cli(['--status', f.out]);
  assert.equal(status.json.status, 'completed');
  assert.match(status.json.progress, /^completed · phase Ask · 2 done, 0 running, 0 failed · \d+m elapsed$/);
  assert.match(status.stderr.trim().split('\n').at(-1), /^progress: completed · /, 'the readable line comes last, where Codex shows it');
  assert.deepEqual(status.json.result, { answers: ['a', 'b'] });
});

test('a detached run returns at once and finishes in the background', async t => {
  const f = await fixture(t, WORKFLOW);
  const start = await cli([f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'gemini', '--executable', fakeCli,
    '--args', '{"items":["x"]}', '--detach']);
  assert.equal(start.code, 0, start.stderr);
  assert.equal(start.json.runDir, f.out);
  let status;
  for (let attempt = 0; attempt < 100; attempt++) {
    status = await cli(['--status', f.out]);
    if (status.json.status !== 'running') break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(status.json.status, 'completed', JSON.stringify(status.json));
  assert.deepEqual(status.json.result, { answers: ['x'] });
  assert.ok(status.json.log.some(line => line.includes('Done ask-x')));
});

test('setup errors fail loudly, and a failed run exits non-zero with its summary', async t => {
  const f = await fixture(t, WORKFLOW);
  const missing = await cli(['--backend', 'codex']);
  assert.equal(missing.code, 1);
  assert.match(missing.stderr, /Pass exactly one workflow script/);

  const noHost = await cli([f.script, '--out', f.out], { CODEX_THREAD_ID: '', CLAUDECODE: '', GEMINI_CLI: '' });
  assert.match(noHost.stderr, /pass --backend/);

  const nothing = await fixture(t, `await agent('echo x')`);
  const failed = await cli([nothing.script, '--out', nothing.out, '--backend', 'gemini', '--executable', fakeCli]);
  assert.equal(failed.code, 1);
  assert.equal(failed.json.status, 'failed');
  assert.equal(failed.json.error.code, 'NO_RESULT');
});

test('inside Codex\'s sandbox, workers run there with a Codex folder of their own', async t => {
  const f = await fixture(t, WORKFLOW);
  const realHome = path.join(f.base, 'codex-real');
  const tmp = path.join(f.base, 'tmp');
  await mkdir(realHome);
  await mkdir(tmp);
  await writeFile(path.join(realHome, 'auth.json'), '{"fake":"login"}');
  const env = { CODEX_SANDBOX: 'seatbelt', CODEX_HOME: realHome, TMPDIR: tmp, FAKE_CLI_LOG: f.log };
  const launch = [f.script, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--sandbox', 'workspace-write', '--args', '{"items":["a"]}'];
  const done = await cli(launch, env);
  assert.equal(done.code, 0, done.stderr);
  // No --out: the run directory is somewhere the sandbox can write.
  assert.ok(done.json.runDir.startsWith(path.join(tmp, 'workflow-runs', 'demo-')), done.json.runDir);
  assert.ok(done.json.notes.some(note => note.includes("Workers run inside this session's sandbox")));
  const [worker] = await readLog(f.log);
  const values = flag => worker.argv.flatMap((arg, i) => arg === flag ? [worker.argv[i + 1]] : []);
  assert.deepEqual(values('--sandbox'), ['danger-full-access']);
  assert.deepEqual(values('--add-dir'), []);
  assert.ok(values('--config').includes(`shell_environment_policy.set.UV_CACHE_DIR=${JSON.stringify(path.join(tmp, 'workflow-runner-cache', 'uv'))}`));
  assert.equal(worker.codexHome, path.join(done.json.runDir, 'codex-home'));
  assert.equal(worker.codexAuth, '{"fake":"login"}');
  assert.ok(!existsSync(worker.codexHome), 'the private Codex folder is removed when the run ends');
  assert.equal((await cli(['--status', done.json.runDir], env)).json.status, 'completed');

  for (const [extra, reason] of [[{ CODEX_SANDBOX_NETWORK_DISABLED: '1' }, /no network access/], [{}, /read-only sandbox/]]) {
    const args = Object.keys(extra).length ? launch : launch.map(arg => arg === 'workspace-write' ? 'read-only' : arg);
    const refused = await cli(args, { ...env, ...extra });
    assert.equal(refused.code, 1);
    assert.match(refused.stderr, /NEEDS_ESCALATION/);
    assert.match(refused.stderr, reason);
  }
  // A run resumes the way it was launched: escalated records stay out of the sandbox's reach.
  const moved = await cli(['--resume', done.json.runDir], { CODEX_HOME: realHome });
  assert.match(moved.stderr, /launched inside the sandbox/);
});

test('an escalated launch starts outside the sandbox, and defaults its records to the Codex folder', async t => {
  const f = await fixture(t, WORKFLOW);
  const realHome = path.join(f.base, 'codex-real');
  await mkdir(realHome);
  // An escalated command still sees CODEX_SANDBOX_NETWORK_DISABLED, and must start.
  const done = await cli([f.script, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--args', '{"items":["a"]}'],
    { CODEX_SANDBOX_NETWORK_DISABLED: '1', CODEX_HOME: realHome });
  assert.equal(done.code, 0, done.stderr);
  assert.ok(done.json.runDir.startsWith(path.join(realHome, 'workflow-runs', 'demo-')), done.json.runDir);
  assert.equal((await cli(['--status', done.json.runDir], { CODEX_SANDBOX: 'seatbelt' })).json.status, 'completed');
  const inside = await cli(['--resume', done.json.runDir], { CODEX_SANDBOX: 'seatbelt', CODEX_HOME: realHome });
  assert.match(inside.stderr, /NEEDS_ESCALATION.*launched with escalated permissions/);
});

test('a writing run refuses run records where its workers can write', async t => {
  const f = await fixture(t, WORKFLOW);
  for (const out of [path.join(f.cwd, 'run'), f.out]) {
    const refused = await cli([f.script, '--out', out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--sandbox', 'workspace-write']);
    assert.equal(refused.code, 1, out);
    assert.match(refused.stderr, /workers can write/);
  }
});

test('--resume never launches a program named in the run records', async t => {
  const f = await fixture(t, `const a = await agent('echo one'); const b = await agent('echo two'); return [a, b]`);
  const stop = new AbortController();
  await assert.rejects(runWorkflow({ script: f.script, cwd: f.cwd, backend: 'codex', executable: fakeCli }, {
    out: f.out, signal: stop.signal,
    execute: async job => { if (taskOf(job).includes('two')) { stop.abort(); throw new RunnerError('ABORTED', 'x'); } return reply('ONE'); },
  }));
  // What a prompt-injected worker would do if it could write the run records.
  const marker = path.join(f.base, 'planted-ran');
  const planted = path.join(f.base, 'planted.sh');
  await writeFile(planted, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
  const statePath = path.join(f.out, 'state.json');
  const state = await readJson(statePath);
  state.settings.executable = planted;
  await writeFile(statePath, JSON.stringify(state));
  // Resumed as the skill does it, without --executable: `codex` is found on PATH again.
  const bin = path.join(f.base, 'bin');
  await mkdir(bin);
  await writeFile(path.join(bin, 'codex'), `#!/bin/sh\nexec '${process.execPath}' '${fakeCli}' "$@"\n`, { mode: 0o755 });
  const resumed = await cli(['--resume', f.out], { PATH: `${bin}${path.delimiter}${process.env.PATH}` });
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.deepEqual(resumed.json.result, ['ONE', 'two']);
  assert.ok(!existsSync(marker), 'the program named in state.json ran');
});

test('the preflight stops a launch that could only fail, without a model call', async t => {
  const f = await fixture(t, WORKFLOW);
  const base = [f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--args', '{"items":["a"]}'];
  const loggedOut = await cli(base, { FAKE_LOGIN_EXIT: '1' });
  assert.equal(loggedOut.code, 1);
  assert.match(loggedOut.stderr, /not logged in/);
  const oldCli = await cli(base, { FAKE_MISSING_FLAG: '--ephemeral' });
  assert.equal(oldCli.code, 1);
  assert.match(oldCli.stderr, /does not support --ephemeral/);
});

test('--cancel stops a detached run, which can then be resumed', async t => {
  const f = await fixture(t, `const a = await agent('echo one'); const b = await agent('hang'); return [a, b]`);
  const start = await cli([f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--detach']);
  assert.equal(start.code, 0, start.stderr);
  for (let i = 0; i < 100 && !(await cli(['--status', f.out])).json.running.length; i++) await new Promise(r => setTimeout(r, 100));
  const cancelled = await cli(['--cancel', f.out]);
  assert.equal(cancelled.json.status, 'interrupted', JSON.stringify(cancelled.json));
  assert.match(cancelled.json.next, /--resume/);
});

test('--resume needs only the run directory', async t => {
  const f = await fixture(t, `const a = await agent('echo one'); const b = await agent('hang'); return [a, b]`);
  const first = await cli([f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--timeout-ms', '500']);
  assert.equal(first.code, 0, first.stderr);
  assert.deepEqual(first.json.result, ['one', null], 'the hung worker timed out to null');
  // --executable again: CI has no codex on PATH, and a resume never reuses the recorded one.
  const again = await cli(['--resume', f.out, '--executable', fakeCli]);
  assert.match(again.stderr, /already completed/);
  const misuse = await cli(['--resume', f.out, '--model', 'x']);
  assert.match(misuse.stderr, /takes only a run directory/);
});

test('process identity prevents stale PIDs from being treated as the runner', () => {
  const original = { pid: process.pid, processIdentity: 'started-original' };
  assert.equal(isRunActive(original, () => 'started-original'), true);
  assert.equal(isRunActive(original, () => 'started-reused'), false);
  assert.equal(isRunActive(original, () => null), false);
  // ps could not answer: trust the live pid.
  assert.equal(isRunActive(original, () => undefined), true);
  assert.equal(isRunActive({ ...original, pid: 2 ** 22 + 12345 }, () => 'started-original'), false);
});

test('cancel does not signal a reused live PID', async t => {
  const f = await fixture(t, '');
  await mkdir(f.out);
  const state = { status: 'running', pid: process.pid, processIdentity: 'different-start', jobs: {}, notes: [],
    usage: { outputTokens: 0 }, startedAt: new Date().toISOString() };
  await writeFile(path.join(f.out, 'state.json'), JSON.stringify(state));
  const result = await cli(['--cancel', f.out]);
  assert.equal(result.code, 1, result.stderr);
  assert.equal(result.json.status, 'stopped');
});

test('cancel fails if the runner does not stop', { timeout: 5000 }, async t => {
  const f = await fixture(t, '');
  await mkdir(f.out);
  const child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000)"],
    { stdio: ['ignore', 'pipe', 'ignore'] });
  t.after(() => child.kill('SIGKILL'));
  await new Promise(resolve => child.stdout.once('data', resolve));
  const state = { status: 'running', pid: child.pid, processIdentity: 'test-start', jobs: {}, notes: [], usage: { outputTokens: 0 } };
  await writeFile(path.join(f.out, 'state.json'), JSON.stringify(state));
  await assert.rejects(cancel(f.out, { timeoutMs: 50, pollMs: 10, identify: () => 'test-start' }), error => error.code === 'CANCEL_TIMEOUT');
  assert.ok(isRunActive(state, () => 'test-start'));
});

test('a detached launch is not reported started until the run records its start', async t => {
  for (const exits of [true, false]) {
    const f = await fixture(t, '');
    let killed = false;
    const child = new EventEmitter();
    Object.assign(child, { pid: 123, unref: () => {}, kill: () => { killed = true; } });
    const spawnRunner = () => { if (exits) setTimeout(() => child.emit('exit', null, 'SIGKILL'), 1); return child; };
    await assert.rejects(detach([], f.out, false, { spawnRunner, timeoutMs: 30, pollMs: 5 }),
      error => exits ? /exited before starting.*SIGKILL/s.test(error.message) : error.code === 'STARTUP_TIMEOUT');
    assert.equal(killed, !exits);
  }
});

test('an invalid structured reply keeps its token usage, so the budget still stops later agents', async t => {
  const f = await fixture(t, `const schema = { type: 'object', properties: { n: { type: 'integer' } }, required: ['n'] };
    const first = await agent('json {broken', { schema });
    const next = await agent('echo should-not-run').catch(e => e.code);
    return { first, next };`);
  const result = await cli([f.script, '--out', f.out, '--cwd', f.cwd, '--backend', 'codex', '--executable', fakeCli, '--token-budget', '1'],
    { FAKE_CLI_LOG: f.log });
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(result.json.result, { first: null, next: 'BUDGET' });
  assert.equal(result.json.outputTokens, 5);
  assert.equal(result.json.workersWithoutUsage, undefined);
  assert.equal((await readLog(f.log)).length, 1);
});
