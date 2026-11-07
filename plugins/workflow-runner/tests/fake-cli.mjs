#!/usr/bin/env node
// Stands in for the codex and gemini CLIs. The task text after the last
// "Task:" line picks the behavior; every invocation's argv is appended to
// $FAKE_CLI_LOG so tests can assert on the flags a worker received.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';

const argv = process.argv.slice(2);
// The runner's preflight: `login status` and `exec --help`, with no model call.
if (argv[0] === 'login' && argv[1] === 'status') { console.log('Logged in using a fake'); process.exit(Number(process.env.FAKE_LOGIN_EXIT ?? 0)); }
if (argv[0] === 'exec' && argv.includes('--help')) {
  const flags = ['--json', '--ephemeral', '--skip-git-repo-check', '--cd', '--sandbox', '--add-dir', '--disable', '--output-schema', '--output-last-message'];
  console.log(flags.filter(flag => flag !== process.env.FAKE_MISSING_FLAG).join('\n'));
  process.exit(0);
}
const backend = argv[0] === 'exec' ? 'codex' : 'gemini';
const flag = name => { const index = argv.indexOf(name); return index === -1 ? undefined : argv[index + 1]; };
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  if (process.env.FAKE_CLI_LOG) {
    const codexHome = process.env.CODEX_HOME;
    const codexAuth = codexHome && existsSync(path.join(codexHome, 'auth.json')) ? readFileSync(path.join(codexHome, 'auth.json'), 'utf8') : null;
    appendFileSync(process.env.FAKE_CLI_LOG, `${JSON.stringify({ backend, argv, pid: process.pid, pluginRoot: process.env.CLAUDE_PLUGIN_ROOT, codexHome, codexAuth })}\n`);
  }
  // Gemini workers get the schema instruction appended after the task.
  const task = input.split('Task:\n').at(-1).split('\n\nReply with only a JSON value')[0].trim();
  const [command, ...rest] = task.split(' ');
  const payload = rest.join(' ');
  if (command === 'hang' && !(process.env.FAKE_HANG_ONCE && existsSync(process.env.FAKE_HANG_ONCE))) {
    if (process.env.FAKE_HANG_ONCE) writeFileSync(process.env.FAKE_HANG_ONCE, 'started');
    setInterval(() => {}, 1000); return;
  }
  if (command === 'flood') {
    const chunk = Buffer.alloc(1024 * 1024, 'x');
    const timer = setInterval(() => { process.stdout.write(chunk); process.stderr.write(chunk); }, 1);
    process.on('SIGTERM', () => { clearInterval(timer); process.exit(0); });
    return;
  }
  if (command === 'exit') { process.stderr.write('simulated crash\n'); process.exit(3); }
  if (command === 'stubborn') {
    // The child reports its pid only once it ignores SIGTERM, and this process waits for
    // that: exiting first would let the runner's SIGTERM land before the handler exists.
    const ready = `process.on('SIGTERM', () => {}); require('fs').writeFileSync(${JSON.stringify(process.env.FAKE_PID_FILE)}, String(process.pid)); setInterval(() => {}, 1000)`;
    spawn(process.execPath, ['-e', ready], { stdio: 'ignore' }).unref();
    const deadline = Date.now() + 5000;
    while (!existsSync(process.env.FAKE_PID_FILE) && Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
  if (command === 'orphan') {
    // Leaves a grandchild holding stdout open after this process exits.
    spawn('sleep', ['30'], { stdio: ['ignore', 'inherit', 'inherit'] }).unref();
  }
  const answer = command === 'fail' ? null : command === 'echo' || command === 'json' ? payload : command === 'orphan' ? 'orphaned' : command === 'stubborn' ? 'left a child' : task;
  if (backend === 'codex') {
    const events = [{ type: 'thread.started', thread_id: 'fake-thread' }, { type: 'turn.started' }];
    if (command === 'flaky') events.push({ type: 'error', message: 'Reconnecting... 1/5' });
    if (answer === null) {
      events.push({ type: 'turn.failed', error: { message: 'simulated failure' } });
    } else {
      events.push({ type: 'item.completed', item: { type: 'agent_message', text: answer } });
      events.push({ type: 'turn.completed', usage: { input_tokens: 100, cached_input_tokens: 0, output_tokens: 5 } });
      writeFileSync(flag('--output-last-message'), answer);
    }
    process.stdout.write(events.map(event => JSON.stringify(event)).join('\n') + '\n');
    process.exitCode = answer === null ? 1 : 0;
  } else {
    process.stdout.write(JSON.stringify(answer === null
      ? { error: { message: 'simulated failure' } }
      : { response: answer, session_id: 'fake-session', stats: { models: { fake: { tokens: { prompt: 100, candidates: 3, thoughts: 2 } } } } }));
  }
});
