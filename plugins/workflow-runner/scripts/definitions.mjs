import { access, readFile, realpath, readdir } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { RunnerError } from './errors.mjs';

export const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

// Fields that change what an agent may do. The runner cannot honor them on
// other hosts, and ignoring one (disallowedTools, hooks) would widen the role.
const CAPABILITY_FIELDS = ['permissionMode', 'isolation', 'skills', 'hooks', 'mcpServers', 'disallowedTools'];
const TOOL_NAME = /[A-Za-z][\w-]*(?:\([^)]*\))?/g;

// A top-level `key: value` line, with the key bare or quoted as YAML allows.
const KEY = /^(?:"([^"]+)"|'([^']+)'|([A-Za-z_][\w-]*))\s*:(?:\s+(.*))?$/;

// Parses only the frontmatter fields that affect dispatch. Agent files are
// plain enough that a YAML dependency would cost more than it buys.
export function parseDefinition(source, file = 'agent definition') {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match) throw new RunnerError('CONFIG', `${file} has no YAML frontmatter`);
  const uncomment = text => {
    let quote = null;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote) {
        if (quote === '"' && c === '\\') { i++; continue; }
        if (c === quote) {
          if (quote === "'" && text[i + 1] === "'") { i++; continue; }
          quote = null;
        }
      } else if (c === '"' || c === "'") quote = c;
      else if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) return text.slice(0, i).trimEnd();
    }
    return text;
  };
  const scalar = text => {
    text = text.trim();
    if (text.startsWith('"')) return JSON.parse(text);
    if (text.startsWith("'")) return text.slice(1, -1).replaceAll("''", "'");
    return text;
  };
  const fields = {};
  const rawLines = match[1].split(/\r?\n/);
  const content = rawLines.filter(line => line.trim() && !line.trimStart().startsWith('#'));
  const indent = Math.min(...content.map(line => line.match(/^ */)[0].length));
  const lines = rawLines.map(line => uncomment(line.slice(indent)));
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    // Blank lines, comments, and indented continuations of an earlier value.
    if (!line.trim() || line.startsWith('#') || /^\s/.test(line)) continue;
    const field = line.match(KEY);
    // Anything else could hide a key this parser would then ignore, silently widening the role.
    if (!field) throw new RunnerError('UNSUPPORTED', `${file}: unsupported frontmatter line: ${line}`);
    const key = field[1] ?? field[2] ?? field[3];
    const text = field[4] ?? '';
    if (!['name', 'model', 'tools', ...CAPABILITY_FIELDS].includes(key)) continue;
    if (Object.hasOwn(fields, key)) throw new RunnerError('CONFIG', `${file}: duplicate field ${key}`);
    if (CAPABILITY_FIELDS.includes(key)) throw new RunnerError('UNSUPPORTED', `${file}: the ${key} field cannot be honored outside Claude Code`);
    if (key !== 'tools') { fields[key] = scalar(text); continue; }
    const body = text.trim();
    // Tool names may carry Claude's scope patterns, such as Bash(git log:*), which contain
    // spaces and colons, so split on names rather than on separators.
    const names = list => list.replace(/["']/g, '').match(TOOL_NAME) ?? [];
    if (body.startsWith('[')) {
      if (!body.endsWith(']')) throw new RunnerError('CONFIG', `${file}: malformed tools list`);
      fields.tools = names(body.slice(1, -1));
    } else if (body) fields.tools = names(body);
    else {
      fields.tools = [];
      while (index + 1 < lines.length) {
        if (!lines[index + 1].trim()) { index++; continue; }
        if (!/^\s+-\s+/.test(lines[index + 1])) break;
        fields.tools.push(scalar(lines[++index].replace(/^\s+-\s+/, '')));
      }
    }
  }
  if (fields.tools && (!fields.tools.length || fields.tools.some(tool => !/^[A-Za-z][\w-]*(\([^)]*\))?$/.test(tool)))) {
    throw new RunnerError('CONFIG', `${file}: tools must be a non-empty list of tool names`);
  }
  return { ...fields, body: source.slice(match[0].length) };
}

async function manifest(directory) {
  try { return JSON.parse(await readFile(path.join(directory, '.claude-plugin/plugin.json'), 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function entries(directory) {
  try { return await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}

// The workflow's own plugin (the nearest ancestor with a manifest) plus the
// exact plugin roots the caller supplied. Nothing is discovered by searching:
// a guessed copy of a dependency could be a different version or a fixture.
export async function loadRegistry(script, extraRoots = []) {
  let owner = path.dirname(await realpath(script));
  while (!await manifest(owner)) {
    const parent = path.dirname(owner);
    if (parent === owner) throw new RunnerError('CONFIG', `${script} is not inside a plugin (no .claude-plugin/plugin.json above it)`);
    owner = parent;
  }
  const plugins = new Map();
  const agents = new Map();
  const skills = new Map();
  for (const supplied of [owner, ...extraRoots]) {
    let root;
    try { root = await realpath(supplied); }
    catch { throw new RunnerError('CONFIG', `Plugin root does not exist: ${supplied}`); }
    const data = await manifest(root);
    if (!data) throw new RunnerError('CONFIG', `No .claude-plugin/plugin.json in plugin root ${root}`);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(data.name ?? '')) throw new RunnerError('CONFIG', `Invalid plugin name at ${root}`);
    if (plugins.has(data.name)) {
      if (plugins.get(data.name) === root) continue;
      throw new RunnerError('CONFIG', `Two different roots for plugin ${data.name}; pass exactly one installed version`);
    }
    plugins.set(data.name, root);
    for (const item of await entries(path.join(root, 'agents'))) {
      if (!item.isFile() || !item.name.endsWith('.md')) continue;
      const file = path.join(root, 'agents', item.name);
      const source = await readFile(file, 'utf8');
      // Parsed on use: an unrelated agent with host-specific fields must not block the run.
      agents.set(`${data.name}:${item.name.slice(0, -3)}`, { file, source, root, hash: digest(source) });
    }
    // Claude Code also exposes legacy commands as skills; SKILL.md wins a name collision.
    for (const item of await entries(path.join(root, 'commands'))) {
      if (item.isFile() && item.name.endsWith('.md')) skills.set(`${data.name}:${item.name.slice(0, -3)}`, path.join(root, 'commands', item.name));
    }
    for (const item of await entries(path.join(root, 'skills'))) {
      if (!item.isDirectory()) continue;
      const file = path.join(root, 'skills', item.name, 'SKILL.md');
      if (await fileExists(file)) skills.set(`${data.name}:${item.name}`, file);
    }
  }
  return { owner, roots: [...plugins.values()], agents, skills };
}

async function fileExists(file) {
  try { await access(file); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

export function resolveRole(registry, name) {
  if (name === undefined || name === null || name === '') return null;
  if (typeof name !== 'string') throw new RunnerError('CONFIG', 'agentType must be a string');
  const entry = registry.agents.get(name);
  if (!entry) {
    const hint = name.includes(':') ? 'supply its plugin with --plugin-root' : 'agent types are namespaced as <plugin>:<agent>';
    throw new RunnerError('ROLE_NOT_FOUND', `Agent type ${name} not found; ${hint}`);
  }
  const parsed = parseDefinition(entry.source, entry.file);
  return { name, file: entry.file, root: entry.root, hash: entry.hash, model: parsed.model, tools: parsed.tools,
    body: parsed.body.replaceAll('{baseDir}', entry.root) };
}
