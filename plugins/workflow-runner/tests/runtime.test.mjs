import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { compile, runWorkflow } from '../scripts/runtime.mjs';
import { parseDefinition } from '../scripts/definitions.mjs';
import { RunnerError } from '../scripts/errors.mjs';
import { fixture, readJson, reply, repo, taskOf } from './helpers.mjs';

const run = (f, execute, settings = {}, options = {}) =>
  runWorkflow({ script: f.script, cwd: f.cwd, backend: 'codex', ...settings }, { out: f.out, execute, ...options });
const echo = async job => reply(taskOf(job));
const rejects = (promise, code) => assert.rejects(promise, error => { assert.equal(error.code, code, error.message); return true; });

test('every repository workflow compiles, and finding none is a failure', async () => {
  let count = 0;
  for (const plugin of await readdir(path.join(repo, 'plugins'))) {
    const dir = path.join(repo, 'plugins', plugin, 'workflows');
    const files = await readdir(dir).catch(error => { if (error.code === 'ENOENT') return []; throw error; });
    for (const file of files.filter(name => name.endsWith('.js'))) {
      compile(await readFile(path.join(dir, file), 'utf8'), file);
      count++;
    }
  }
  assert.ok(count >= 11, `expected at least 11 workflows, found ${count}`);
});

test('repository workflows stay inside the API the runner supports', async () => {
  // Compiling cannot catch these: they fail only when the call is reached, mid-run.
  const unsupported = [/\bworkflow\s*\(/, /\bisolation\s*:/];
  assert.match("await workflow('x')", unsupported[0]);
  assert.match("agent(p, { isolation: 'worktree' })", unsupported[1]);
  let scanned = 0;
  for (const plugin of await readdir(path.join(repo, 'plugins'))) {
    const dir = path.join(repo, 'plugins', plugin, 'workflows');
    const files = await readdir(dir).catch(error => { if (error.code === 'ENOENT') return []; throw error; });
    for (const file of files.filter(name => name.endsWith('.js'))) {
      const source = await readFile(path.join(dir, file), 'utf8');
      for (const pattern of unsupported) assert.doesNotMatch(source, pattern, `${plugin}/workflows/${file} uses ${pattern}`);
      scanned++;
    }
  }
  assert.ok(scanned >= 11, `expected at least 11 workflows, found ${scanned}`);
});

test('pipeline passes (previous, original, index) and keeps item order', async t => {
  const f = await fixture(t, `return await pipeline(args, (item, original, index) => agent(item + index),
    (previous, original, index) => agent(JSON.stringify({ previous, original, index })))`);
  const summary = await run(f, echo, { args: ['a', 'b'] });
  assert.deepEqual(summary.result.map(JSON.parse), [{ previous: 'a0', original: 'a', index: 0 }, { previous: 'b1', original: 'b', index: 1 }]);
  assert.equal(summary.outputTokens, 20);
});

test('a failed worker is a null result that the summary still reports', async t => {
  const f = await fixture(t, `return await parallel([() => agent('ok', { label: 'good' }), () => agent('boom', { label: 'bad' })])`);
  const summary = await run(f, async job => {
    if (taskOf(job) === 'boom') throw new RunnerError('EXIT', 'worker crashed');
    return reply('fine');
  });
  assert.deepEqual(summary.result, ['fine', null]);
  assert.equal(summary.status, 'completed');
  assert.deepEqual(summary.workerFailures.map(failure => [failure.label, failure.error.code]), [['bad', 'EXIT']]);
  assert.match(await readFile(path.join(summary.workerFailures[0].dir, 'error.json'), 'utf8'), /worker crashed/);
});

test('agent() configuration errors reach the script\'s own catch, and are listed in the notes', async t => {
  // spec-compliance and code-improver catch an unresolved agent type and fall back.
  const f = await fixture(t, `return await agent('x', { agentType: 'demo:missing' }).catch(error => agent('fallback after: ' + error.message))`);
  const summary = await run(f, echo);
  assert.equal(summary.status, 'completed');
  assert.match(summary.result, /^fallback after: Agent type demo:missing not found/);
  assert.ok(summary.notes.some(note => /agent\(\) rejected: Agent type demo:missing/.test(note)));

  const g = await fixture(t, `return await parallel([() => agent('x', { agentType: 'demo:missing' }), () => agent('ok')])`);
  const branches = await run(g, echo);
  assert.deepEqual(branches.result, [null, 'ok']);
  assert.ok(branches.notes.some(note => /Agent type demo:missing/.test(note)), 'a misconfigured branch must not be a silent null');

  // Uncaught at the top level, the script throws and the run fails, as natively.
  for (const [body, code] of [
    [`return await agent('x', { isolation: 'worktree' })`, 'UNSUPPORTED'],
    [`return await agent('x', { schema: { type: 'string' } })`, 'SCHEMA_CONFIG'],
    [`return await workflow('other')`, 'UNSUPPORTED'],
  ]) {
    const h = await fixture(t, body);
    await rejects(run(h, echo), code);
  }
});

test('a run that dispatches nothing returns its own value; one that leaves work running or returns nothing fails', async t => {
  // insecure-defaults reports a missing plugin root this way, before any agent runs.
  const f = await fixture(t, `return { status: 'missing-plugin-root', note: 'pass pluginRoot' }`);
  const summary = await run(f, echo);
  assert.deepEqual(summary.result, { status: 'missing-plugin-root', note: 'pass pluginRoot' });
  assert.ok(summary.notes.includes('The workflow made no agent() calls.'));
  for (const [body, code] of [[`agent('slow'); return 1`, 'UNAWAITED'], [`await agent('x')`, 'NO_RESULT']]) {
    const g = await fixture(t, body);
    await rejects(run(g, echo), code);
  }
});

test('a workflow script inside the target directory is refused', async t => {
  const f = await fixture(t, `return await agent('x')`);
  const planted = path.join(f.cwd, 'planted');
  await cp(f.plugin, planted, { recursive: true });
  await assert.rejects(runWorkflow({ script: path.join(planted, 'workflows/demo.js'), cwd: f.cwd, backend: 'codex' }, { out: f.out, execute: echo }),
    error => error.code === 'CONFIG' && /workers can write/.test(error.message));
});

test('network reaches only roles that can run commands', async t => {
  const agents = {
    reader: '---\nname: reader\ntools: Read, Grep, Glob, Write\n---\nRead.',
    runner: '---\nname: runner\ntools: Read, Bash\n---\nRun.',
  };
  const f = await fixture(t, `return [await agent('a', { agentType: 'demo:reader' }), await agent('b', { agentType: 'demo:runner' }), await agent('c')]`, { agents });
  const network = [];
  await run(f, async job => { network.push(job.network); return reply('ok'); }, { sandbox: 'workspace-write', network: true });
  assert.deepEqual(network, [false, true, true], 'a role Claude gives no shell must not reach the network');
});

test('workers take the launching session\'s sandbox, narrowed to read-only for roles that cannot write', async t => {
  const agents = {
    reader: '---\nname: reader\ntools: [Read, Grep]\n---\nRead from {baseDir}.',
    writer: '---\nname: writer\ndescription: "writes: reports"\ntools:\n  - Read\n  - Write\n---\nWrite.',
  };
  const body = `return [await agent('r', { agentType: 'demo:reader' }), await agent('w', { agentType: 'demo:writer' }), await agent('plain')]`;
  const f = await fixture(t, body, { agents });
  const jobs = [];
  await run(f, async job => { jobs.push(job); return reply('ok'); }, { sandbox: 'workspace-write' });
  assert.deepEqual(jobs.map(job => job.sandbox), ['read-only', 'workspace-write', 'workspace-write']);
  assert.deepEqual(jobs[0].tools, ['Read', 'Grep']);
  assert.match(jobs[0].prompt, new RegExp(`Read from ${f.plugin}\\.`));
  // The same heading Claude Code gives its skill listing; workflows look for it by name.
  assert.match(jobs[0].prompt, /The following skills are available for use with the Skill tool/);
  assert.match(jobs[0].prompt, new RegExp(`- demo:reader: ${f.plugin}/agents/reader\\.md`));
  assert.equal(jobs[0].env.CLAUDE_PLUGIN_ROOT, f.plugin);

  const g = await fixture(t, body, { agents });
  await rejects(run(g, async () => reply('ok')), 'PERMISSIONS');

  const h = await fixture(t, body, { agents });
  const full = [];
  await run(h, async job => { full.push(job.sandbox); return reply('ok'); }, { sandbox: 'danger-full-access' });
  assert.deepEqual(full, ['read-only', 'danger-full-access', 'danger-full-access']);
});

test('Codex workers in a writing run may write the caches of tools their plugin uses; read-only runs may not', async t => {
  const base = (await fixture(t, '')).cwd;
  const home = path.join(base, 'home');
  const bin = path.join(base, 'bin');
  await mkdir(bin, { recursive: true });
  await writeFile(path.join(bin, 'codeql'), '#!/bin/sh\n', { mode: 0o755 });
  const env = { ...process.env, HOME: home, PATH: bin };
  const body = `// builds a codeql database\nreturn [await agent('w'), await agent('r', { agentType: 'demo:reader' })]`;
  const agents = { reader: '---\nname: reader\ntools: [Read, Grep]\n---\nRead.' };
  const f = await fixture(t, body, { agents });
  const jobs = [];
  const summary = await run(f, async job => { jobs.push(job); return reply('ok'); }, { sandbox: 'workspace-write' }, { env });
  assert.deepEqual(jobs[0].cacheDirs, [path.join(home, '.codeql')], 'codeql is on PATH; uv and semgrep are not');
  assert.ok((await readdir(home)).includes('.codeql'), 'a missing cache is created so the first run can fill it');
  assert.match(summary.notes.join(' '), /tool caches/);
  const g = await fixture(t, `// builds a codeql database\nreturn await agent('r')`);
  const readOnly = [];
  await run(g, async job => { readOnly.push(job); return reply('ok'); }, {}, { env });
  assert.deepEqual(readOnly[0].cacheDirs, []);
  const h = await fixture(t, `return await agent('w')`);
  const unused = [];
  await run(h, async job => { unused.push(job); return reply('ok'); }, { sandbox: 'workspace-write' }, { env });
  assert.deepEqual(unused[0].cacheDirs, [], 'a plugin that never mentions codeql gets no write access to its cache');
});

test('agents from a supplied plugin root run with that plugin as their root', async t => {
  const f = await fixture(t, `return await agent('x', { agentType: 'helper:checker' })`);
  const helper = path.join(f.cwd, 'elsewhere', 'helper');
  await mkdir(path.join(helper, '.claude-plugin'), { recursive: true });
  await mkdir(path.join(helper, 'agents'));
  await writeFile(path.join(helper, '.claude-plugin/plugin.json'), '{"name":"helper","version":"1.0.0"}');
  await writeFile(path.join(helper, 'agents/checker.md'), '---\nname: checker\nmodel: inherit\n---\nCheck.');
  const jobs = [];
  await run(f, async job => { jobs.push(job); return reply('ok'); }, { pluginRoots: [helper] });
  assert.equal(jobs[0].env.CLAUDE_PLUGIN_ROOT, helper);
  assert.equal(jobs[0].model, undefined);
});

test('structured results are validated, and an invalid one is a worker failure', async t => {
  const schema = `{ type: 'object', properties: { n: { type: 'integer' } }, required: ['n'] }`;
  const f = await fixture(t, `return [await agent('good', { schema: ${schema} }), await agent('bad', { schema: ${schema} })]`);
  const summary = await run(f, async job => reply(taskOf(job) === 'good' ? { n: 1 } : { n: 'one' }));
  assert.deepEqual(summary.result, [{ n: 1 }, null]);
  assert.equal(summary.workerFailures[0].error.code, 'SCHEMA');
});

test('Claude model names fall back to the CLI default elsewhere, with one note', async t => {
  const body = `return [await agent('a', { model: 'sonnet' }), await agent('b', { model: 'opus', effort: 'max' }), await agent('c', { model: 'gpt-5.5' })]`;
  const f = await fixture(t, body);
  const jobs = [];
  const summary = await run(f, async job => { jobs.push(job); return reply('ok'); });
  assert.deepEqual(jobs.map(job => [job.model, job.effort]), [[undefined, undefined], [undefined, 'xhigh'], ['gpt-5.5', undefined]]);
  assert.equal(summary.notes.length, 3);

  const g = await fixture(t, body);
  const overridden = [];
  await run(g, async job => { overridden.push(job.model); return reply('ok'); }, { model: 'gpt-5.5-mini' });
  assert.deepEqual(overridden, ['gpt-5.5-mini', 'gpt-5.5-mini', 'gpt-5.5-mini']);

});

test('budget follows the native contract: null without a target, then a hard stop', async t => {
  const f = await fixture(t, `return { total: budget.total, remaining: budget.remaining(), value: await agent('x') }`);
  assert.deepEqual((await run(f, echo)).result, { total: null, remaining: Infinity, value: 'x' });

  const g = await fixture(t, `const done = [await agent('a'), await agent('b')]
    let third
    try { third = await agent('c') } catch (error) { third = error.message }
    return { done, third, spent: budget.spent(), remaining: budget.remaining(), late: await parallel([() => agent('d')]) }`);
  const summary = await run(g, async job => reply(taskOf(job), 6), { tokenBudget: 10 });
  assert.deepEqual(summary.result, { done: ['a', 'b'], third: 'Token budget exhausted', spent: 12, remaining: 0, late: [null] });
});

test('calls queued for a slot do not start once the budget is spent', async t => {
  const f = await fixture(t, `return await parallel([1, 2, 3].map(n => () => agent('job ' + n)))`);
  const started = [];
  const summary = await run(f, async job => { started.push(taskOf(job)); return reply(taskOf(job), 5); }, { tokenBudget: 1, concurrency: 1 });
  assert.deepEqual(started, ['job 1'], 'queued calls ran after the budget was spent');
  assert.deepEqual(summary.result, ['job 1', null, null]);
});

test('a failed worker with unknown usage does not stop a budgeted run', async t => {
  const f = await fixture(t, `return [await agent('a'), await parallel([() => agent('b')])]`);
  const summary = await run(f, async job => {
    if (taskOf(job) === 'a') throw new RunnerError('TIMEOUT', 'worker timed out');
    return reply('b', 5);
  }, { tokenBudget: 1_000_000 });
  assert.deepEqual(summary.result, [null, ['b']]);
  assert.equal(summary.outputTokens, 5);
  assert.equal(summary.workersWithoutUsage, 1);
});

test('Date.now(), new Date() and Math.random() throw, as they do natively', async t => {
  for (const expression of ['Date.now()', 'new Date()', 'Math.random()']) {
    const f = await fixture(t, `await agent('x'); return ${expression}`);
    await assert.rejects(run(f, echo), /unavailable in workflows/);
  }
  const f = await fixture(t, `await agent('x'); return new Date(0).toISOString()`);
  assert.equal((await run(f, echo)).result, '1970-01-01T00:00:00.000Z');
});

test('the dispatch cap fails the run', async t => {
  const f = await fixture(t, `for (let i = 0; i < 5; i++) await agent('x' + i); return 1`);
  await rejects(run(f, echo, { maxAgents: 3 }), 'DISPATCH_LIMIT');
});

test('a run directory is never reused', async t => {
  const f = await fixture(t, `return await agent('x')`);
  await run(f, echo);
  await rejects(run(f, echo), 'CONFIG');
});

test('resume reruns the first failed agent and every agent after it, as Claude Code does', async t => {
  const f = await fixture(t, `return [await agent('a'), await agent('b'), await agent('c'), await agent('d')]`);
  const stop = new AbortController();
  await rejects(run(f, async job => {
    const task = taskOf(job);
    if (task === 'b') throw new RunnerError('EXIT', 'worker crashed');
    if (task === 'd') { stop.abort(); throw new RunnerError('ABORTED', 'x'); }
    return reply(task.toUpperCase());
  }, {}, { signal: stop.signal }), 'INTERRUPTED');
  const executed = [];
  const settings = (await readJson(path.join(f.out, 'state.json'))).settings;
  const summary = await runWorkflow(settings, { out: f.out, resume: true, execute: async job => { executed.push(taskOf(job)); return reply(taskOf(job)); } });
  assert.deepEqual(executed, ['b', 'c', 'd'], 'c completed before, but it came after the failed b');
  assert.deepEqual(summary.result, ['A', 'b', 'c', 'd']);
});

test('on macOS, sandboxed Codex workers get the system certificate bundle', { skip: process.platform !== 'darwin' }, async t => {
  const f = await fixture(t, `return await agent('x')`);
  const env = { ...process.env };
  delete env.SSL_CERT_FILE;
  const jobs = [];
  await run(f, async job => { jobs.push(job); return reply('ok'); }, { sandbox: 'workspace-write' }, { env });
  assert.equal(jobs[0].certFile, '/etc/ssl/cert.pem');
  assert.equal(jobs[0].env.SSL_CERT_FILE, undefined, 'only the worker\'s commands get it, not the codex binary');
});

test('a note says so when every agent failed', async t => {
  const f = await fixture(t, `return await parallel([() => agent('a'), () => agent('b')])`);
  const summary = await run(f, async () => { throw new RunnerError('WORKER', 'not logged in'); });
  assert.deepEqual(summary.result, [null, null]);
  assert.ok(summary.notes.some(note => /Every agent failed.*not logged in/.test(note)));
});

test('resume replays completed agents, follows script edits, and refuses changed settings', async t => {
  const f = await fixture(t, `const a = await agent('first'); const b = await agent('second:' + a); return [a, b]`);
  const controller = new AbortController();
  await rejects(run(f, async job => {
    if (taskOf(job).startsWith('second')) { controller.abort(); throw new RunnerError('ABORTED', 'cancelled'); }
    return reply('A');
  }, {}, { signal: controller.signal }), 'INTERRUPTED');
  const state = await readJson(path.join(f.out, 'state.json'));
  assert.equal(state.status, 'interrupted');

  const executed = [];
  const summary = await runWorkflow(state.settings, { out: f.out, resume: true, execute: async job => { executed.push(taskOf(job)); return reply('B'); } });
  assert.deepEqual(summary.result, ['A', 'B']);
  assert.deepEqual(executed, ['second:A']);
  await rejects(runWorkflow(state.settings, { out: f.out, resume: true, execute: echo }), 'CONFIG');

  // As natively, an edited script resumes: agents replay up to the first call that changed.
  const g = await fixture(t, `const a = await agent('first'); const b = await agent('second'); return [a, b, await agent('third')]`);
  const stop = new AbortController();
  await rejects(run(g, async job => { if (taskOf(job) === 'third') { stop.abort(); throw new RunnerError('ABORTED', 'x'); } return reply(taskOf(job)); }, {}, { signal: stop.signal }), 'INTERRUPTED');
  await writeFile(g.script, (await readFile(g.script, 'utf8')).replace("'second'", "'edited'"));
  const edited = [];
  const resumed = await runWorkflow((await readJson(path.join(g.out, 'state.json'))).settings, { out: g.out, resume: true, execute: async job => { edited.push(taskOf(job)); return reply(taskOf(job)); } });
  assert.deepEqual(edited, ['edited', 'third']);
  assert.deepEqual(resumed.result, ['first', 'edited', 'third']);

  // Settings are part of what a run is; tampered ones do not resume.
  const h = await fixture(t, `const a = await agent('first'); return [a, await agent('hang')]`);
  const halt = new AbortController();
  await rejects(run(h, async job => { if (taskOf(job) === 'hang') { halt.abort(); throw new RunnerError('ABORTED', 'x'); } return reply('A'); }, {}, { signal: halt.signal }), 'INTERRUPTED');
  const tampered = (await readJson(path.join(h.out, 'state.json'))).settings;
  tampered.sandbox = 'danger-full-access';
  await assert.rejects(runWorkflow(tampered, { out: h.out, resume: true, execute: echo }), /changed since this run started/);
});

test('agent frontmatter: inline, comma and block tool lists; capability fields refused', () => {
  assert.deepEqual(parseDefinition('---\nname: a\ntools: [Read, "Grep"]\n---\nbody').tools, ['Read', 'Grep']);
  assert.deepEqual(parseDefinition('---\nname: a\ntools: Read, Grep, Glob, Write\n---\n').tools, ['Read', 'Grep', 'Glob', 'Write']);
  assert.deepEqual(parseDefinition('---\nname: a\ndescription: |\n  tools: not this\ntools:\n  - Read\n  - Bash\nmodel: haiku\n---\n'), { name: 'a', tools: ['Read', 'Bash'], model: 'haiku', body: '' });
  assert.throws(() => parseDefinition('---\nname: a\ndisallowedTools: Bash\n---\n'), /disallowedTools/);
  assert.throws(() => parseDefinition('no frontmatter'), /frontmatter/);
  // Claude's scoped tool patterns: Bash(git log:*) is still Bash.
  assert.deepEqual(parseDefinition('---\ntools: Bash(git log:*), Read\n---\n').tools, ['Bash(git log:*)', 'Read']);
  assert.deepEqual(parseDefinition('---\ntools: [Read, "Bash(npm test:*)"]\n---\n').tools, ['Read', 'Bash(npm test:*)']);
  assert.deepEqual(parseDefinition('---\n"name": a\n"tools": [Read]\n---\n').tools, ['Read'], 'a quoted key is still a key');
  assert.deepEqual(parseDefinition("---\n'tools':\n  - Grep\n---\n").tools, ['Grep']);
  assert.throws(() => parseDefinition('---\nname: a\n"disallowedTools": [Bash]\n---\n'), /disallowedTools/);
  assert.throws(() => parseDefinition('---\n{tools: [Read]}\n---\n'), /unsupported frontmatter/);
  assert.throws(() => parseDefinition('---\n? tools\n: [Read]\n---\n'), /unsupported frontmatter/);
});

test('frontmatter comments and indentation cannot widen tool capabilities', () => {
  for (const value of ['Read # Bash excluded', '[Read] # Bash excluded', '"Read" # Bash excluded', "'Read' # Bash excluded"]) {
    const parsed = parseDefinition(`---\n  name: reader\n  tools: ${value}\n  model: inherit # comment\n---\n`);
    assert.deepEqual(parsed.tools, ['Read']);
    assert.equal(parsed.model, 'inherit');
  }
  for (const key of ['disallowedTools', 'permissionMode', 'hooks']) {
    assert.throws(() => parseDefinition(`---\n  name: reader\n  tools: [Read]\n  ${key}: [Bash]\n---\n`), error => error.code === 'UNSUPPORTED');
  }
  assert.deepEqual(parseDefinition('---\ntools:\n  - Read\n  # another tool\n  - Bash # command tool\n---\n').tools, ['Read', 'Bash']);
  assert.equal(parseDefinition('---\nmodel: "model#1" # comment\n---\n').model, 'model#1');
});

test('branch exceptions and budget skips are durable notes', async t => {
  const f = await fixture(t, `await agent('spend'); return await parallel([
    () => { throw null }, () => { throw 'boom' }, () => { throw new Error('broken') }, () => agent('skipped')])`);
  const summary = await run(f, echo, { tokenBudget: 1 });
  assert.deepEqual(summary.result, [null, null, null, null]);
  const saved = await readJson(path.join(f.out, 'state.json'));
  for (const text of ['Branch failed: null', 'Branch failed: boom', 'Branch failed: broken', 'Token budget exhausted']) {
    assert.ok(summary.notes.some(note => note.includes(text)), text);
    assert.ok(saved.notes.some(note => note.includes(text)), text);
  }
});

const until = async predicate => {
  const deadline = Date.now() + 3000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, 'condition did not become true');
    await new Promise(resolve => setTimeout(resolve, 5));
  }
};

test('concurrency limits actual activity and releases slots after worker failures', async t => {
  const f = await fixture(t, `return await parallel([1,2,3,4].map(n=>()=>agent(String(n))))`);
  let active = 0;
  let peak = 0;
  const gates = [];
  const running = run(f, async job => {
    active++; peak = Math.max(peak, active);
    try { return await new Promise((resolve, reject) => gates.push({ resolve, reject, task: taskOf(job) })); }
    finally { active--; }
  }, { concurrency: 2 });
  await until(() => gates.length === 2);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(gates.length, 2);
  gates[0].reject(new RunnerError('EXIT', 'failed'));
  await until(() => gates.length === 3);
  assert.equal(active, 2);
  gates[1].resolve(reply('second'));
  await until(() => gates.length === 4);
  gates[2].resolve(reply('third')); gates[3].resolve(reply('fourth'));
  const summary = await running;
  assert.equal(peak, 2);
  assert.equal(active, 0);
  const expected = {};
  gates.forEach((gate,i) => { expected[gate.task] = [null,'second','third','fourth'][i]; });
  assert.deepEqual(summary.result, ['1','2','3','4'].map(task => expected[task]));
});

async function interrupted(t, body, execute = echo) {
  const f = await fixture(t, body);
  const stop = new AbortController();
  await rejects(run(f, async job => {
    if (taskOf(job) === 'stop') { stop.abort(); throw new RunnerError('ABORTED', 'stop'); }
    return execute(job);
  }, {}, { signal: stop.signal }), 'INTERRUPTED');
  return { ...f, settings: (await readJson(path.join(f.out, 'state.json'))).settings };
}

test('resume refuses a substituted completed result', async t => {
  const f = await interrupted(t, `await agent('a'); return await agent('stop')`);
  const state = await readJson(path.join(f.out, 'state.json'));
  const completed = Object.values(state.jobs).find(job => job.status === 'completed');
  await writeFile(path.join(completed.dir, 'result.json'), '{"value":"substituted"}');
  let calls = 0;
  await assert.rejects(runWorkflow(f.settings, { out: f.out, resume: true, execute: async () => { calls++; return reply('bad'); } }), /Recorded result.*modified/);
  assert.equal(calls, 0);
});
