import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { commandArgs, decode, detectBackend, executeWorker, findExecutable, prepareCodexHome, roleRunsCommands, roleWrites, toolCacheEnv } from '../scripts/backends.mjs';
import { checkSchema, restoreOptional, strictSchema, validate } from '../scripts/schema.mjs';
import { killPending, runProcess } from '../scripts/process.mjs';
import { readFile, readlink, readdir, writeFile } from 'node:fs/promises';
import { fakeCli, fixture, readLog } from './helpers.mjs';

test('the host is detected from exactly one marker', () => {
  assert.equal(detectBackend({ CODEX_THREAD_ID: 't' }), 'codex');
  assert.throws(() => detectBackend({ CLAUDECODE: '1' }), /native Workflow tool/);
  assert.equal(detectBackend({ GEMINI_CLI: '1' }), 'gemini');
  assert.throws(() => detectBackend({}), /pass --backend/);
  assert.throws(() => detectBackend({ CODEX_THREAD_ID: 't', GEMINI_CLI: '1' }), /Several host markers/);
});

test('the sandbox maps onto each host\'s own sandbox or approval mode', () => {
  const base = { cwd: '/w', answerPath: '/r/a', addDirs: ['/out'], readDirs: ['/plugins/p'] };
  const codexRead = commandArgs('codex', { ...base, sandbox: 'read-only', network: false });
  assert.equal(codexRead[codexRead.indexOf('--sandbox') + 1], 'read-only');
  assert.ok(!codexRead.includes('--add-dir'), 'write directories mean nothing in a read-only sandbox');
  const codexWrite = commandArgs('codex', { ...base, cacheDirs: ['/home/.cache/uv'], sandbox: 'workspace-write', network: true, effort: 'high', model: 'gpt-5.5', schemaPath: '/r/s.json' });
  assert.ok(!commandArgs('codex', { ...base, cacheDirs: ['/home/.cache/uv'], sandbox: 'read-only' }).includes('/home/.cache/uv'));
  for (const expected of ['workspace-write', 'sandbox_workspace_write.network_access=true', '/out', '/home/.cache/uv', 'model_reasoning_effort="high"', 'gpt-5.5', '/r/s.json', 'multi_agent']) {
    assert.ok(codexWrite.includes(expected), `codex args lack ${expected}`);
  }
  assert.equal(codexWrite.at(-1), '-');


  assert.ok(!codexWrite.some(arg => arg.includes('approval_policy')), 'approvals follow the user\'s Codex config');
  const cert = commandArgs('codex', { ...base, sandbox: 'workspace-write', certFile: '/etc/ssl/cert.pem' });
  assert.ok(cert.includes('shell_environment_policy.set.SSL_CERT_FILE="/etc/ssl/cert.pem"'));
  assert.ok(roleRunsCommands({ tools: ['Bash(git log:*)', 'Read'] }) && !roleWrites({ tools: ['Bash(git log:*)', 'Read'] }));
  const full = commandArgs('codex', { ...base, cacheDirs: ['/home/.cache/uv'], sandbox: 'danger-full-access' });
  assert.equal(full[full.indexOf('--sandbox') + 1], 'danger-full-access');
  assert.ok(!full.includes('--add-dir'), 'nothing to add when every directory is writable');
  assert.equal(commandArgs('gemini', { ...base, sandbox: 'danger-full-access' }).at(3), 'yolo');
  const gemini = commandArgs('gemini', { ...base, sandbox: 'workspace-write' });
  assert.equal(gemini[gemini.indexOf('--approval-mode') + 1], 'auto_edit');
  assert.deepEqual(gemini.filter((_, i) => gemini[i - 1] === '--include-directories'), ['/plugins/p', '/out']);
});

test('decoding: a transient Codex error before a completed turn is not a failure', () => {
  const lines = events => events.map(event => JSON.stringify(event)).join('\n');
  const ok = decode('codex', lines([{ type: 'error', message: 'Reconnecting 1/5' }, { type: 'turn.completed', usage: { output_tokens: 4 } }]), 'answer');
  assert.deepEqual([ok.text, ok.outputTokens, ok.diagnostics], ['answer', 4, ['Reconnecting 1/5']]);
  assert.throws(() => decode('codex', lines([{ type: 'turn.failed', error: { message: 'quota' } }]), 'x'), /quota/);
  assert.throws(() => decode('codex', lines([{ type: 'error', message: 'gone' }]), undefined), /gone/);
  assert.equal(decode('gemini', JSON.stringify({ response: 'r', stats: { models: { a: { tokens: { candidates: 2, thoughts: 3 } }, b: { tokens: { candidates: 1 } } } } })).outputTokens, 6);
});

test('optional schema properties survive Codex strict output', () => {
  const schema = { type: 'object', properties: { a: { type: 'string' }, b: { type: ['string', 'null'] }, list: { type: 'array', items: { type: 'object', properties: { x: { type: 'integer' } } } } }, required: ['a'] };
  checkSchema(schema);
  const strict = strictSchema(schema);
  assert.deepEqual(strict.required, ['a', 'b', 'list']);
  assert.equal(strict.additionalProperties, false);
  const value = restoreOptional({ a: 'x', b: null, list: [{ x: null }] }, schema);
  assert.deepEqual(value, { a: 'x', b: null, list: [{}] }, 'b explicitly allows null; x was only a placeholder');
  validate(value, schema);
  assert.throws(() => checkSchema({ type: 'object', properties: { m: { type: 'object', additionalProperties: { type: 'string' } } } }), /Map-shaped/);

  const branching = { type: 'object', required: ['item'], properties: { item: { anyOf: [
    { type: 'object', properties: { a: { type: 'string' }, b: { type: 'string' } }, required: ['a'] }, { type: 'string' }] } } };
  checkSchema(branching);
  const restored = restoreOptional({ item: { a: 'x', b: null } }, branching);
  assert.deepEqual(restored, { item: { a: 'x' } }, 'the placeholder inside an anyOf branch is removed');
  validate(restored, branching);
  assert.equal(restoreOptional({ item: 'plain' }, branching).item, 'plain');
});

test('each backend runs end to end through a real process', async t => {
  const f = await fixture(t, '');
  const schema = { type: 'object', properties: { ok: { type: 'boolean' }, note: { type: 'string' } }, required: ['ok'] };
  for (const backend of ['codex', 'gemini']) {
    const directory = path.join(f.cwd, backend);
    await mkdir(directory);
    const job = { backend, cwd: f.cwd, directory, sandbox: 'read-only', env: { ...process.env, FAKE_CLI_LOG: f.log } };
    const plain = await executeWorker({ ...job, prompt: 'preamble\n\nTask:\necho hello' }, { executable: fakeCli, timeoutMs: 10_000 });
    assert.equal(plain.value, 'hello', backend);
    assert.ok(plain.outputTokens > 0, backend);
    const structured = await executeWorker({ ...job, schema, prompt: 'Task:\njson {"ok":true,"note":null}' }, { executable: fakeCli, timeoutMs: 10_000 });
    assert.deepEqual(structured.value, backend === 'codex' ? { ok: true } : { ok: true, note: null }, backend);
    await assert.rejects(executeWorker({ ...job, prompt: 'Task:\nfail' }, { executable: fakeCli, timeoutMs: 10_000 }), error => error.code === 'WORKER' || error.code === 'EXIT');
  }
  const invocations = await readLog(f.log);
  assert.equal(invocations.length, 6);
  assert.ok(invocations.find(entry => entry.backend === 'codex' && entry.argv.includes('--output-schema')));
});

test('a worker that hangs is stopped at its timeout', async () => {
  const started = Date.now();
  await assert.rejects(runProcess(fakeCli, ['exec'], { input: 'Task:\nhang', timeoutMs: 300, env: process.env }), error => error.code === 'TIMEOUT');
  assert.ok(Date.now() - started < 8000, 'timeout took too long to settle');
});

test('a worker that exits but leaves a process holding its pipes still settles', async () => {
  const started = Date.now();
  const result = await runProcess(fakeCli, [], { input: 'Task:\norphan', timeoutMs: 20_000, env: process.env });
  assert.match(result.stdout, /orphaned/);
  assert.ok(Date.now() - started < 8000, 'settling waited for the orphan');
});

const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const gone = async (pid, ms) => {
  for (let waited = 0; waited < ms; waited += 50) { if (!alive(pid)) return true; await new Promise(r => setTimeout(r, 50)); }
  return !alive(pid);
};

test('a TERM-resistant child is killed even after the worker\'s pipes close', async t => {
  const f = await fixture(t, '');
  const pidFile = path.join(f.cwd, 'child.pid');
  const result = await runProcess(fakeCli, [], { input: 'Task:\nstubborn', timeoutMs: 10_000, env: { ...process.env, FAKE_PID_FILE: pidFile } });
  const pid = Number(await readFile(pidFile, 'utf8'));
  t.after(() => { try { process.kill(pid, 'SIGKILL'); } catch {} });
  assert.match(result.stdout, /left a child/);
  assert.ok(await gone(pid, 5000), 'the SIGTERM-ignoring child survived its worker');
});

test('killPending stops leftover children at once, for a runner that is exiting', async t => {
  const f = await fixture(t, '');
  const pidFile = path.join(f.cwd, 'child.pid');
  await runProcess(fakeCli, [], { input: 'Task:\nstubborn', timeoutMs: 10_000, env: { ...process.env, FAKE_PID_FILE: pidFile } });
  const pid = Number(await readFile(pidFile, 'utf8'));
  t.after(() => { try { process.kill(pid, 'SIGKILL'); } catch {} });
  killPending();
  assert.ok(await gone(pid, 1000), 'killPending did not stop the child before the grace period ended');
});

test('binaries come only from absolute PATH entries', async t => {
  const f = await fixture(t, '');
  const bin = path.join(f.base, 'bin');
  await mkdir(bin);
  await writeFile(path.join(bin, 'codex'), '#!/bin/sh\n', { mode: 0o755 });
  assert.equal(findExecutable('codex', { PATH: path.relative(process.cwd(), bin) }), null, 'a relative PATH entry is skipped');
  assert.equal(findExecutable('codex', { PATH: ['.', bin].join(path.delimiter) }), path.join(bin, 'codex'));
});

test('a crashing or missing CLI is a worker failure with its stderr', async () => {
  await assert.rejects(runProcess(fakeCli, ['exec'], { input: 'Task:\nexit', timeoutMs: 10_000, env: process.env }), error => error.code === 'EXIT' && /simulated crash/.test(error.message));
  await assert.rejects(runProcess('/nonexistent/codex', [], { timeoutMs: 10_000, env: process.env }), error => error.code === 'LAUNCH');
});

test('Codex flags preserve exact flag-value associations', () => {
  for (const sandbox of ['read-only', 'workspace-write', 'danger-full-access']) {
    const args = commandArgs('codex', { cwd:'/target', sandbox, addDirs:['/extra'], cacheDirs:['/cache'],
      model:'gpt-example', effort:'high', schemaPath:'/schema.json', answerPath:'/answer.txt', network:false });
    const values = flag => args.flatMap((arg,i) => arg === flag ? [args[i+1]] : []);
    for (const [flag, expected] of Object.entries({ '--disable':['multi_agent'], '--sandbox':[sandbox], '--cd':['/target'],
      '--model':['gpt-example'], '--output-schema':['/schema.json'], '--output-last-message':['/answer.txt'], '--color':['never'] })) {
      assert.deepEqual(values(flag), expected, flag);
    }
    assert.deepEqual(values('--add-dir'), sandbox === 'workspace-write' ? ['/extra','/cache'] : []);
    assert.deepEqual(values('--config'), [...(sandbox === 'workspace-write' ? ['sandbox_workspace_write.network_access=false'] : []), 'model_reasoning_effort="high"']);
    for (const flag of ['--json','--ephemeral','--skip-git-repo-check']) assert.equal(args.filter(x => x === flag).length, 1);
    assert.equal(args.at(-1), '-');
    assert.ok(!args.includes('--enable'));
  }
});

test('nullable object schemas retain null in required and optional nested properties', () => {
  for (const required of [[], ['item']]) {
    const schema = { type:'object', properties:{ item:{ type:['object','null'], properties:{ n:{type:'integer'} }, required:['n'] } }, required };
    const strict = strictSchema(schema);
    for (const value of [{item:null}, {item:{n:1}}]) {
      validate(value, strict);
      assert.deepEqual(restoreOptional(value, schema), value);
    }
  }
});

test('structured decoding accepts a single JSON fence and retains usage on malformed replies', async t => {
  const f = await fixture(t, '');
  const schema = { type:'object',properties:{n:{type:'integer'}},required:['n'] };
  for (const backend of ['codex','gemini']) {
    const directory = path.join(f.base,backend); await mkdir(directory);
    const base = { backend, directory, cwd:f.cwd, sandbox:'read-only', schema, env:process.env };
    for (const text of ['{"n":1}', '```json\n{"n":1}\n```']) {
      const result = await executeWorker({...base,prompt:`Task:\njson ${text}`}, {executable:fakeCli,timeoutMs:5000});
      assert.deepEqual(result.value, {n:1});
    }
    for (const text of ['before {"n":1}', '{"n":', '```json\n{"n":1}\n```\nafter']) {
      await assert.rejects(executeWorker({...base,prompt:`Task:\njson ${text}`}, {executable:fakeCli,timeoutMs:5000}), error => {
        assert.equal(error.code,'SCHEMA'); assert.equal(error.outputTokens,5); assert.ok(error.sessionId); return true;
      });
    }
  }
});

test('inside the session\'s sandbox, Codex workers apply no sandbox of their own and move the tool caches', () => {
  const args = commandArgs('codex', { cwd: '/target', sandbox: 'workspace-write', insideSandbox: true, addDirs: ['/extra'],
    cacheDirs: ['/cache'], network: true, toolEnv: toolCacheEnv('/tmp/c'), answerPath: '/answer.txt' });
  const values = flag => args.flatMap((arg, i) => arg === flag ? [args[i + 1]] : []);
  assert.deepEqual(values('--sandbox'), ['danger-full-access']);
  assert.deepEqual(values('--add-dir'), []);
  assert.deepEqual(values('--config'), [
    'shell_environment_policy.set.UV_CACHE_DIR="/tmp/c/uv"',
    'shell_environment_policy.set.UV_TOOL_DIR="/tmp/c/uv-tools"',
    'shell_environment_policy.set.SEMGREP_LOG_FILE="/tmp/c/semgrep/semgrep.log"',
    'shell_environment_policy.set.SEMGREP_VERSION_CACHE_PATH="/tmp/c/semgrep/version"',
  ]);
});

test('a worker\'s own Codex folder links to the user\'s login and settings, and only those', async t => {
  const f = await fixture(t, '');
  const real = path.join(f.base, 'codex-real');
  await mkdir(real);
  await writeFile(path.join(real, 'auth.json'), '{}');
  await writeFile(path.join(real, 'history.jsonl'), '');
  const home = path.join(f.base, 'home');
  for (let i = 0; i < 2; i++) await prepareCodexHome(home, { CODEX_HOME: real });
  assert.deepEqual(await readdir(home), ['auth.json']);
  assert.equal(await readlink(path.join(home, 'auth.json')), path.join(real, 'auth.json'));
});
