// Execute the shipped async workflow body with stubbed agent calls. These tests cover
// orchestration and mutation gates; real native probe fixtures live with the helper.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../workflows/taint-trace-run.js', import.meta.url), 'utf8')
const body = source.replace('export const meta', 'const meta')
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor
const fn = new AsyncFunction('args', 'agent', 'phase', 'log', 'Date', 'Math', body)
class FixedDate extends Date {
  constructor() { super('2026-01-02T03:04:05.000Z') }
}
const fixedMath = Object.create(Math)
fixedMath.random = () => 0.25

const ROOT = '/workspace/app'
const SKILL = '/runtime/.codex/plugins/cache/trailofbits/trailmark/0.13.0/skills/taint-trace'
const RUN = `${ROOT}/.trailmark/taint-trace/runs/20260102T030405000Z-9`
const MANIFEST = `${RUN}/manifest.json`
const CONTEXT = `${RUN}/context-original.json`
const component = (id, language = 'python') => ({
  id, root: `${ROOT}/${id}`, language, backend: 'semgrep', scope: 'intraprocedural', status: 'candidate', reason: '',
})
const active = (c) => ({
  ...c, status: 'limited', reason: 'Single-function analysis.', probe: `${RUN}/${c.id}/probe.json`, baseline: `${RUN}/${c.id}/baseline.json`,
})
const gate = (stage, overrides = {}) => ({
  valid: true, stage, status: 'limited', active_components: 1,
  failed_components: 0, limited_components: 1, skipped_components: 0,
  errors: [], limitations: ['Single-function analysis.'], ...overrides,
})

async function run({ args = {}, components = [component('api')], overrides = {} } = {}) {
  const calls = []
  const prompts = []
  const phases = []
  const logs = []
  const prepared = components.map((c) => c.status === 'candidate' ? active(c) : c)
  const activeCount = prepared.filter((c) => ['analyzed', 'limited'].includes(c.status)).length
  const defaultGate = (stage) => gate(stage, {
    valid: activeCount > 0,
    status: activeCount ? 'limited' : 'failed',
    active_components: activeCount,
    limited_components: activeCount,
    skipped_components: prepared.filter((c) => c.status === 'skipped').length,
    failed_components: prepared.filter((c) => c.status === 'failed').length,
    errors: activeCount ? [] : ['No component has successful native analysis.'],
  })
  const defaults = {
    resolve: () => ({ skill_dir: SKILL, target: ROOT, helper_exists: true, method: 'codex-cache', reason: '' }),
    inventory: () => ({ manifest_path: MANIFEST, context_path: CONTEXT, components }),
    prepare: () => ({ manifest_path: MANIFEST, validation_path: `${RUN}/baseline-gate.json`, validation: defaultGate('baseline'), components: prepared }),
    model: (id) => ({ component_id: id, status: 'modeled', models_added: 1, reason: 'Native wrapper summary.' }),
    analyze: (id) => ({ component_id: id, status: 'limited', reason: 'Single-function analysis.', enriched_path: `${RUN}/${id}/enriched.json`, rejected_models: false }),
    'analyze-retry': (id) => ({ component_id: id, status: 'limited', reason: 'Single-function analysis.', enriched_path: `${RUN}/${id}/enriched-retry.json`, rejected_models: false }),
    repair: (id) => ({ component_id: id, repaired: true, reason: 'Removed rejected native syntax.' }),
    finish: () => ({
      manifest_path: MANIFEST, validation_path: `${RUN}/complete-gate.json`, validation: defaultGate('complete'),
      report_result: { valid: activeCount > 0, status: activeCount ? 'limited' : 'failed', report: `${RUN}/report.md` },
    }),
  }
  const handlers = { ...defaults, ...overrides }
  const agent = async (prompt, opts) => {
    calls.push(opts.label)
    prompts.push({ label: opts.label, prompt })
    const [stage, id] = opts.label.split(':')
    assert.ok(handlers[stage], `Missing stub for ${stage}`)
    return handlers[stage](id, { calls, prompts, prepared, defaultGate })
  }
  try {
    const result = await fn(args, agent, (p) => phases.push(p), (m) => logs.push(m), FixedDate, fixedMath)
    return { result, error: null, calls, prompts, phases, logs }
  } catch (error) {
    return { result: null, error, calls, prompts, phases, logs }
  }
}

test('a successful run returns the deterministic helper status and preserved report', async () => {
  const { result, error, calls, phases } = await run()
  assert.equal(error, null)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'model:api', 'analyze:api', 'finish'])
  assert.deepEqual(phases, ['Inventory', 'Baseline', 'Model', 'Analyze', 'Report'])
  assert.equal(result.status, 'limited')
  assert.equal(result.active_components, 1)
  assert.equal(result.manifest, MANIFEST)
  assert.equal(result.report, `${RUN}/report.md`)
  assert.equal(result.validation, `${RUN}/complete-gate.json`)
})

test('no defensible model gap still runs native comparison and produces a report', async () => {
  const { result, error, calls } = await run({ overrides: {
    model: (id) => ({ component_id: id, status: 'unchanged', models_added: 0, reason: 'The baseline already traces the visible wrapper.' }),
  } })
  assert.equal(error, null)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'model:api', 'analyze:api', 'finish'])
  assert.equal(result.active_components, 1)
  assert.equal(result.report, `${RUN}/report.md`)
})

test('malformed inputs fail before any agent can run', async () => {
  for (const args of [
    'please scan this project', [], { target: '' }, { languages: [] }, { languages: 'PHP and Python' },
    { languages: ['go and java'] }, { backends: { php: 'magic' } }, { backends: [] },
    { focus: [42] }, { skill_dir: 'relative/helper' }, { target: 'a\nb' }, { typo: 'value' },
  ]) {
    const { error, calls } = await run({ args })
    assert.ok(error, JSON.stringify(args))
    assert.deepEqual(calls, [], JSON.stringify(args))
  }
})

test('JSON object strings are accepted and single focus symbols stay data', async () => {
  const { error } = await run({ args: '{"target":".","languages":["php"],"focus":"Database::query","backends":{"php":"psalm"}}' })
  assert.equal(error, null)
})

test('missing installed helpers stop before graph or target edits', async () => {
  const { error, calls } = await run({ overrides: {
    resolve: () => ({ skill_dir: '', target: ROOT, helper_exists: false, method: '', reason: 'No new installation.' }),
  } })
  assert.match(error.message, /Cannot locate.*No new installation/)
  assert.deepEqual(calls, ['resolve'])
})

test('automatic resolution rejects executable helpers found in target content', async () => {
  const { error, calls } = await run({ overrides: {
    resolve: () => ({ skill_dir: `${ROOT}/plugins/trailmark/skills/taint-trace`, target: ROOT, helper_exists: true, method: 'codex-cache', reason: '' }),
  } })
  assert.match(error.message, /known installed plugin cache/)
  assert.deepEqual(calls, ['resolve'])
})

test('cache-shaped helpers inside the target are rejected before execution', async () => {
  for (const cache of ['.claude', '.codex']) {
    const supplied = `${ROOT}/${cache}/plugins/cache/x/trailmark/y/skills/taint-trace`
    const { error, calls } = await run({ overrides: {
      resolve: () => ({ skill_dir: supplied, target: ROOT, helper_exists: true,
        method: cache === '.claude' ? 'claude-cache' : 'codex-cache', reason: '' }),
    } })
    assert.match(error.message, /helper must be outside the target/)
    assert.deepEqual(calls, ['resolve'])
  }
})

test('explicit helpers equal to or inside the target are rejected', async () => {
  for (const supplied of [ROOT, `${ROOT}/skills/taint-trace`]) {
    const { error, calls } = await run({ args: { skill_dir: supplied }, overrides: {
      resolve: () => ({ skill_dir: supplied, target: ROOT, helper_exists: true, method: 'provided', reason: '' }),
    } })
    assert.match(error.message, /helper must be outside the target/)
    assert.deepEqual(calls, ['resolve'])
  }
})

test('an invoking skill can explicitly supply its directory outside the caches', async () => {
  const supplied = '/checkout/plugins/trailmark/skills/taint-trace'
  const { error } = await run({ args: { skill_dir: supplied }, overrides: {
    resolve: () => ({ skill_dir: supplied, target: ROOT, helper_exists: true, method: 'provided', reason: '' }),
  } })
  assert.equal(error, null)
})

test('duplicate component IDs and component roots outside the target are rejected', async () => {
  for (const components of [[component('api'), component('api')], [{ ...component('api'), root: '/outside/app' }]]) {
    const { error, calls } = await run({ components })
    assert.ok(error)
    assert.deepEqual(calls, ['resolve', 'inventory'])
  }
})

test('wholly skipped runs get a failed report and never start modeling', async () => {
  const skipped = { ...component('cairo', 'cairo'), status: 'skipped', reason: 'Native positive probe fails.' }
  const { error, calls } = await run({ components: [skipped] })
  assert.match(error.message, /did not pass artifact validation/)
  assert.match(error.message, /report\.md/)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'finish'])
})

test('a failed deterministic baseline gate blocks all source/model mutation', async () => {
  const { error, calls } = await run({ overrides: {
    prepare: () => ({
      manifest_path: MANIFEST, validation_path: `${RUN}/baseline-gate.json`, components: [active(component('api'))],
      validation: gate('baseline', { valid: false, errors: ['Probe native positive did not match.'] }),
    }),
  } })
  assert.match(error.message, /mutation is blocked/)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'finish'])
})

test('active components without both probe and baseline records cannot reach modeling', async () => {
  for (const absent of ['probe', 'baseline']) {
    const c = active(component('api'))
    delete c[absent]
    const { error, calls } = await run({ overrides: {
      prepare: () => ({ manifest_path: MANIFEST, validation_path: `${RUN}/baseline-gate.json`, components: [c], validation: gate('baseline') }),
    } })
    assert.match(error.message, /lacks preserved probe or baseline/)
    assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'finish'])
  }
})

test('a stale or out-of-run artifact cannot unlock the baseline gate', async () => {
  const { error, calls } = await run({ overrides: {
    prepare: () => ({
      manifest_path: MANIFEST, validation_path: '/tmp/previous-run/gate.json',
      components: [active(component('api'))], validation: gate('baseline'),
    }),
  } })
  assert.match(error.message, /mutation is blocked/)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'finish'])
})

test('preparation cannot activate a language skipped by graph inventory', async () => {
  const skipped = { ...component('cairo', 'cairo'), status: 'skipped', reason: 'No supported native taint backend.' }
  const { error, calls } = await run({ components: [skipped], overrides: {
    prepare: () => ({ manifest_path: MANIFEST, validation_path: `${RUN}/baseline-gate.json`, components: [active(skipped)], validation: gate('baseline') }),
  } })
  assert.match(error.message, /activated excluded component/)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'finish'])
})

test('one failed language does not prevent a usable language from running', async () => {
  const components = [component('api'), { ...component('legacy', 'cairo'), status: 'skipped', reason: 'Failed native positive.' }]
  const { result, error, calls } = await run({ components })
  assert.equal(error, null)
  assert.equal(result.active_components, 1)
  assert.equal(result.skipped_components, 1)
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'model:api', 'analyze:api', 'finish'])
})

test('a modeling-stage failure is isolated and reported while another component continues', async () => {
  const { result, error, calls, prompts } = await run({ components: [component('api'), component('jobs')], overrides: {
    model: (id) => {
      if (id === 'api') throw new Error('Native contract cannot preserve existing configuration.')
      return { component_id: id, status: 'unchanged', models_added: 0, reason: 'No defensible gaps.' }
    },
    finish: () => ({
      manifest_path: MANIFEST, validation_path: `${RUN}/complete-gate.json`,
      validation: gate('complete', { failed_components: 1 }),
      report_result: { valid: true, status: 'limited', report: `${RUN}/report.md` },
    }),
  } })
  assert.equal(error, null)
  assert.equal(result.failed_components, 1)
  assert.ok(!calls.includes('analyze:api'))
  assert.ok(calls.includes('analyze:jobs'))
  assert.match(prompts.find((p) => p.label === 'finish').prompt, /Native contract cannot preserve/)
})

test('native tool model rejection permits exactly one repair and preserves the retry output', async () => {
  const { result, error, calls } = await run({ overrides: {
    analyze: (id) => ({ component_id: id, status: 'failed', reason: 'Invalid generated model.', enriched_path: `${RUN}/${id}/enriched.json`, rejected_models: true }),
  } })
  assert.equal(error, null)
  assert.equal(result.status, 'limited')
  assert.deepEqual(calls, ['resolve', 'inventory', 'prepare', 'model:api', 'analyze:api', 'repair:api', 'analyze-retry:api', 'finish'])
})

test('a second rejection cannot trigger another repair or a third analysis', async () => {
  const reject = (id) => ({ component_id: id, status: 'failed', reason: 'Invalid generated model.', enriched_path: `${RUN}/${id}/rejected.json`, rejected_models: true })
  const { error, calls } = await run({ overrides: {
    analyze: reject, 'analyze-retry': reject,
    finish: () => ({
      manifest_path: MANIFEST, validation_path: `${RUN}/complete-gate.json`,
      validation: gate('complete', { valid: false, status: 'failed', active_components: 0, failed_components: 1, errors: ['No successful component.'] }),
      report_result: { valid: false, status: 'failed', report: `${RUN}/report.md` },
    }),
  } })
  assert.ok(error)
  assert.equal(calls.filter((x) => x.startsWith('repair:')).length, 1)
  assert.equal(calls.filter((x) => x.startsWith('analyze')).length, 2)
})

test('ordinary analyzer failures never request model repair', async () => {
  const { error, calls } = await run({ overrides: {
    analyze: (id) => ({ component_id: id, status: 'failed', reason: 'Build database is unavailable.', enriched_path: `${RUN}/${id}/enriched.json`, rejected_models: false }),
  } })
  assert.ok(!calls.some((x) => x.startsWith('repair:')))
  assert.ok(!calls.some((x) => x.startsWith('analyze-retry:')))
  assert.match(error.message, /counts disagree with completed native analysis/)
})

test('agent prose cannot override a failed final deterministic validation', async () => {
  const { error } = await run({ overrides: {
    finish: () => ({
      manifest_path: MANIFEST, validation_path: `${RUN}/complete-gate.json`,
      validation: gate('complete', { valid: false, errors: ['Native output hash changed.'] }),
      report_result: { valid: true, status: 'limited', report: `${RUN}/report.md` },
      summary: 'Everything passed!',
    }),
  } })
  assert.match(error.message, /Native output hash changed/)
})

test('report status must agree with deterministic validation and stay inside the run', async () => {
  for (const report_result of [
    { valid: true, status: 'analyzed', report: `${RUN}/report.md` },
    { valid: true, status: 'limited', report: '/tmp/elsewhere/report.md' },
  ]) {
    const { error } = await run({ overrides: {
      finish: () => ({ manifest_path: MANIFEST, validation_path: `${RUN}/complete-gate.json`, validation: gate('complete'), report_result }),
    } })
    assert.ok(error)
  }
})

test('shell metacharacters in paths/focus are single-quoted before execution instructions', async () => {
  const dangerous = "/workspace/app's $(touch /tmp/owned)`id`"
  const symbol = "sink'$(touch /tmp/owned)"
  const quote = (x) => `'${x.replace(/'/g, `'\\''`)}'`
  const changedRun = RUN.replace(ROOT, dangerous)
  const changedManifest = `${changedRun}/manifest.json`
  const { prompts } = await run({ args: { target: dangerous, focus: symbol }, overrides: {
    resolve: () => ({ skill_dir: SKILL, target: dangerous, helper_exists: true, method: 'codex-cache', reason: '' }),
    inventory: () => ({ manifest_path: changedManifest, context_path: `${changedRun}/context-original.json`, components: [] }),
  } })
  assert.ok(prompts[0].prompt.includes(quote(dangerous)))
  const contextPrompt = prompts.find((p) => p.label === 'inventory').prompt
  assert.ok(contextPrompt.includes(`--target ${quote(dangerous)}`))
  assert.ok(contextPrompt.includes(`--focus ${quote(symbol)}`))
})
