import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { repo } from './helpers.mjs';

// The sentence every workflow skill carries, verbatim, so that Codex and Gemini users reach
// the runner and the text stays the same across plugins.
export const HANDOFF = "**Outside Claude Code** (no `Workflow` tool): run this skill's workflow with the "
  + '`workflow-runner:run-workflow` skill. If that skill is not installed, say so and stop.';

// Or, for a workflow known not to work under the runner, this prefix and the reason.
export const UNSUPPORTED = "**Outside Claude Code** this skill's workflow is not supported: ";

const list = dir => readdir(dir).catch(error => { if (error.code === 'ENOENT') return []; throw error; });

async function workflowSkills() {
  const found = [];
  for (const plugin of await list(path.join(repo, 'plugins'))) {
    const root = path.join(repo, 'plugins', plugin);
    const workflows = [];
    for (const file of (await list(path.join(root, 'workflows'))).filter(name => name.endsWith('.js'))) {
      const source = await readFile(path.join(root, 'workflows', file), 'utf8');
      workflows.push({ file, name: source.match(/export const meta\s*=\s*\{[\s\S]*?\bname:\s*['"]([^'"]+)['"]/)?.[1] });
    }
    if (!workflows.length) continue;
    const skills = [];
    for (const skill of await list(path.join(root, 'skills'))) {
      const file = path.join(root, 'skills', skill, 'SKILL.md');
      const text = await readFile(file, 'utf8').catch(() => null);
      if (text === null) continue;
      const launches = workflows.some(w => text.includes(`workflows/${w.file}`) || (w.name && text.includes(`${plugin}:${w.name}`)));
      if (launches) skills.push({ file: path.relative(repo, file), text });
    }
    found.push({ plugin, workflows, skills });
  }
  return found;
}

test('every plugin workflow is reachable from a skill outside Claude Code', async () => {
  const plugins = await workflowSkills();
  assert.ok(plugins.length >= 10, `expected at least 10 plugins with workflows, found ${plugins.length}`);
  for (const { plugin, skills } of plugins) {
    assert.ok(skills.length, `${plugin} ships a workflow but no skill launches it; Codex cannot invoke a command`);
  }
});

test('each workflow skill carries the shared hand-off sentence verbatim, or says it is unsupported', async () => {
  const skills = (await workflowSkills()).flatMap(p => p.skills);
  assert.ok(skills.length >= 13, `expected at least 13 workflow skills, found ${skills.length}`);
  for (const { file, text } of skills) {
    assert.ok(text.includes(HANDOFF) || text.includes(UNSUPPORTED), `${file} lacks the shared hand-off sentence`);
  }
});

test('workflow skills resolve their own plugin instead of searching for one', async () => {
  // A search takes whichever copy turns up first: in a live Codex test, code-improver's
  // `find ~/.claude ~/.codex .` launched a stale marketplace snapshot, and nothing said so.
  const search = /\bfind\s+[^\n`]*(~|\$HOME)\/\.(claude|codex)/;
  assert.match("find ~/.claude ~/.codex . -path '*/x/workflows/y.js'", search);
  const skills = (await workflowSkills()).flatMap(p => p.skills);
  assert.ok(skills.length >= 13);
  for (const { file, text } of skills) assert.doesNotMatch(text, search, `${file} searches for its plugin`);
});
