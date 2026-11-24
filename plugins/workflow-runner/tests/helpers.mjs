import { chmod, mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const fakeCli = fileURLToPath(new URL('./fake-cli.mjs', import.meta.url));
export const runner = fileURLToPath(new URL('../scripts/run.mjs', import.meta.url));
export const repo = fileURLToPath(new URL('../../..', import.meta.url));

// A throwaway plugin with one workflow, beside a throwaway target directory. The plugin
// stays outside the target, as an installed one is: the runner refuses scripts inside it.
export async function fixture(t, body, { agents = {}, name = 'demo' } = {}) {
  await chmod(fakeCli, 0o755);
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'workflow-runner-')));
  t.after(() => rm(base, { recursive: true, force: true }));
  const cwd = path.join(base, 'target');
  await mkdir(cwd);
  const plugin = path.join(base, 'plugins', name);
  await mkdir(path.join(plugin, '.claude-plugin'), { recursive: true });
  await mkdir(path.join(plugin, 'workflows'));
  await writeFile(path.join(plugin, '.claude-plugin/plugin.json'), JSON.stringify({ name, version: '1.0.0' }));
  if (Object.keys(agents).length) await mkdir(path.join(plugin, 'agents'));
  for (const [file, source] of Object.entries(agents)) await writeFile(path.join(plugin, 'agents', `${file}.md`), source);
  const script = path.join(plugin, 'workflows', 'demo.js');
  await writeFile(script, `export const meta = { name: 'demo', description: 'test' }\n${body}`);
  return { base, cwd, plugin, script, out: path.join(base, 'run'), log: path.join(base, 'argv.jsonl') };
}

export const readJson = async file => JSON.parse(await readFile(file, 'utf8'));
export const readLog = async file => (await readFile(file, 'utf8')).trim().split('\n').map(line => JSON.parse(line));

// The task the runtime appended after its preamble and any role definition.
export const taskOf = job => job.prompt.split('Task:\n').at(-1);
export const reply = (value, outputTokens = 5) => ({ value, outputTokens, sessionId: 'fake' });
