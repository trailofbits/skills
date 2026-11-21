// Workflow orchestration tests. The Python CLI tests exercise the native artifact gate.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../workflows/specification-assurance.js', import.meta.url), 'utf8')
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor
const workflow = new AsyncFunction('args', 'agent', 'phase', 'log', 'Date', 'Math', source.replace('export const meta', 'const meta'))
const forbiddenDate = class { constructor() { throw new Error('Workflow timestamps are unavailable') } }
const forbiddenMath = { random: () => { throw new Error('Workflow randomness is unavailable') } }
const ROOT = '/workspace/project'
const RUN = `${ROOT}/.trailmark/specification-assurance/runs/run-12345678`
const SKILL = '/plugins/trailmark/skills/specification-assurance'
const requirements = ['a'.repeat(20), 'b'.repeat(20)].map((id) => ({
  id, specification: 'spec.md', section: 'packets', level: 'MUST', quote: 'Packets MUST be bounded.',
}))

async function run({ root = ROOT, skill = SKILL, input = { specifications: ['spec.md'], skill_dir: skill }, handlers = {} } = {}) {
  const runDir = `${root}/.trailmark/specification-assurance/runs/run-12345678`
  const calls = []
  const phases = []
  const defaults = {
    resolve: () => ({ target: root, run: runDir, reason: '' }),
    setup: () => ({ status: 'ready', reason: '', source_files: 3, requirements, limitations: [] }),
    assess: (id) => ({ id, record_path: `${runDir}/requirements/${id}.json`, record_sha256: 'c'.repeat(64) }),
    report: () => ({ report_path: `${runDir}/report.md`, ledger_path: `${runDir}/ledger.json` }),
  }
  const all = { ...defaults, ...handlers }
  const agent = async (prompt, options) => {
    calls.push(options.label)
    const [stage, id] = options.label.split(':')
    return all[stage](id, { prompt, defaults })
  }
  try {
    const result = await workflow(input, agent, (value) => phases.push(value), () => {}, forbiddenDate, forbiddenMath)
    return { result, calls, phases }
  } catch (error) {
    return { error, calls, phases }
  }
}

test('every original requirement is assessed and the native gate remains pending', async () => {
  const { error, result, calls, phases } = await run()
  assert.equal(error, undefined)
  assert.deepEqual(calls, ['resolve', 'setup', ...requirements.map((r) => `assess:${r.id}`), 'report'])
  assert.deepEqual(phases, ['Setup', 'Assess', 'Report'])
  assert.equal(result.total, 2)
  assert.equal(result.report, `${RUN}/report.md`)
  assert.equal(result.status, 'pending_validation')
  assert.match(result.validation_command, / finalize /)
  assert.equal(result.validation_request_path, `${RUN}/validation-request.json`)
  assert.deepEqual(result.validation_request.specifications, ['spec.md'])
  assert.equal(result.validation_request.production_source_files, 3)
  assert.deepEqual(result.validation_request.requirements, requirements.map((r) => r.id))
  assert.deepEqual(result.validation_request.assessments,
    Object.fromEntries(requirements.map(({ id }) => [id, 'c'.repeat(64)])))
})

test('agent claims of a supported gate never substitute for native execution', async () => {
  // No report, ledger, logs, or gate file exists. Plausible agent JSON can only
  // prepare a pending handoff, never an assurance verdict or a validated link.
  const { error, result } = await run({ handlers: {
    report: (_, { defaults }) => ({ ...defaults.report(), duvet_ok: true,
      gate: { valid: true, status: 'supported', total: 2, verdicts: { supported: 2 }, limitations: [], errors: [] } }),
  } })
  assert.equal(error, undefined)
  assert.equal(result.status, 'pending_validation')
  assert.equal(result.duvet_ok, undefined)
})

test('malformed inputs fail before tools or target mutations', async () => {
  for (const input of [{}, 'scan everything', [], { specifications: [] }, { specifications: [42] },
    { specifications: ['https://example.com/spec.md'] },
    { specifications: ['spec.md'], target: 'a\nb' }, { specifications: ['spec.md'], skill_dir: 'relative' },
    { specifications: ['spec.md'], ignore_errors: true }]) {
    const { error, calls } = await run({ input })
    assert.ok(error, JSON.stringify(input))
    assert.deepEqual(calls, [])
  }
})

test('direct invocation requires an explicit trusted skill directory', async () => {
  const { error, calls } = await run({ input: { specifications: ['spec.md'] } })
  assert.match(error.message, /skill_dir/)
  assert.deepEqual(calls, [])
})

test('the resolver cannot substitute a helper from the target checkout', async () => {
  const untrusted = `${ROOT}/plugins/trailmark/skills/specification-assurance`
  const { error, result } = await run({ handlers: {
    resolve: (_, { defaults }) => ({ ...defaults.resolve(), skill_dir: untrusted }),
    setup: (_, { prompt, defaults }) => {
      assert.ok(prompt.includes(`${SKILL}/scripts/requirements.py`))
      assert.ok(!prompt.includes(`${untrusted}/scripts/requirements.py`))
      return defaults.setup()
    },
  } })
  assert.equal(error, undefined)
  assert.ok(result.validation_command.includes(`${SKILL}/scripts/requirements.py`))
  assert.ok(!result.validation_command.includes(untrusted))
})

test('setup uses the isolated baseline runner and freezes the tree before workers', async () => {
  const { error } = await run({ handlers: {
    setup: (_, { prompt, defaults }) => {
      assert.ok(prompt.includes(' baseline --root '))
      assert.ok(prompt.includes(' begin --root '))
      assert.ok(prompt.includes(' freeze --root '))
      assert.ok(prompt.indexOf(' begin --root ') < prompt.indexOf('Capture the assessed baseline'))
      assert.ok(prompt.indexOf('Capture the assessed baseline') < prompt.indexOf('Build a fresh implementation graph'))
      assert.ok(prompt.indexOf('Build a fresh implementation graph') < prompt.indexOf(' freeze --root '))
      assert.ok(!prompt.includes('Capture unannotated baseline using duvet report'))
      return defaults.setup()
    },
  } })
  assert.equal(error, undefined)
})

test('empty native setup or an invalid inventory never reaches assessment', async () => {
  for (const update of [{ source_files: 0 }, { requirements: [] }, { status: 'failed' },
    { requirements: [null] }, { requirements: [{ ...requirements[0], quote: '' }] },
    { requirements: [requirements[0], requirements[0]] }]) {
    const { error, calls } = await run({ handlers: {
      setup: (_, { defaults }) => ({ ...defaults.setup(), ...update }),
    } })
    assert.ok(error)
    assert.deepEqual(calls, ['resolve', 'setup'])
  }
})

test('run paths must belong to the target and be allocated without runtime randomness', async () => {
  for (const path of ['/tmp/run-12345678', `${RUN}/../other`, `${RUN}/nested`, `${RUN}/nested/run-87654321`]) {
    const { error, calls } = await run({ handlers: {
      resolve: (_, { defaults }) => ({ ...defaults.resolve(), run: path }),
    } })
    assert.ok(error)
    assert.deepEqual(calls, ['resolve'])
  }
})

test('worker failures retain their exact identities and do not discard later requirements', async () => {
  for (const failure of [new Error('Native verifier unavailable'), new Error(''), null]) {
    const { error, result, calls } = await run({ handlers: {
      assess: (id, { defaults }) => {
        if (id === requirements[0].id) throw failure
        return defaults.assess(id)
      },
      report: (_, { prompt, defaults }) => {
        assert.ok(prompt.includes('"status": "failed"'))
        assert.ok(!prompt.includes('"record_path": "",\n    "error": ""'))
        return defaults.report()
      },
    } })
    assert.equal(error, undefined)
    assert.equal(result.status, 'pending_validation')
    assert.ok(calls.includes(`assess:${requirements[1].id}`))
    assert.deepEqual(result.failed_requirements, [requirements[0].id])
    assert.deepEqual(result.validation_request.failed_requirements, [requirements[0].id])
    assert.deepEqual(Object.keys(result.validation_request.assessments), [requirements[1].id])
  }
})

test('setup limitations are passed to the deterministic checker', async () => {
  const { error, result } = await run({ handlers: {
    setup: (_, { defaults }) => ({ ...defaults.setup(), limitations: ['Unsupported formal source'] }),
  } })
  assert.equal(error, undefined)
  assert.deepEqual(result.validation_request.limitations, ['Unsupported formal source'])
})

test('missing or malformed worker digests remain failed assessments', async () => {
  for (const record_sha256 of [undefined, '', 'c'.repeat(63), 'g'.repeat(64)]) {
    const { error, result } = await run({ handlers: {
      assess: (id, { defaults }) => ({ ...defaults.assess(id), record_sha256 }),
    } })
    assert.equal(error, undefined)
    assert.deepEqual(result.failed_requirements, requirements.map((item) => item.id))
    assert.deepEqual(result.validation_request.assessments, {})
  }
})

test('unexpected report paths are rejected before the handoff', async () => {
  const { error } = await run({ handlers: {
    report: (_, { defaults }) => ({ ...defaults.report(), report_path: '/old/report.md' }),
  } })
  assert.match(error.message, /Unexpected assurance artifact paths/)
})

test('shell tokens preserve apostrophes, spaces, and injection-shaped text', async () => {
  const suffix = "team's $(printf INJECTED); `printf INJECTED` & files"
  const target = `./${suffix}`
  const root = `/workspace/${suffix}`
  const skill = `/plugins/${suffix}/specification-assurance`
  const specification = `spec/${suffix}.md`
  const { error, result } = await run({ root, skill, input: { target, specifications: [specification], skill_dir: skill }, handlers: {
    resolve: (_, { prompt, defaults }) => {
      const token = prompt.match(/Target shell token: (.*)\. Explicit skill directory:/)[1]
      assert.equal(execFileSync('/bin/sh', ['-c', `printf '%s' ${token}`], { encoding: 'utf8' }), target)
      return defaults.resolve()
    },
  } })
  assert.equal(error, undefined)
  const directory = mkdtempSync(join(tmpdir(), 'assurance-shell-'))
  try {
    writeFileSync(join(directory, 'uv'), '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify(process.argv.slice(2)))\n', { mode: 0o755 })
    const argv = JSON.parse(execFileSync('/bin/sh', ['-c', result.validation_command], {
      encoding: 'utf8', env: { ...process.env, PATH: `${directory}:${process.env.PATH}` },
    }))
    assert.deepEqual(argv.slice(0, 3), ['run', '--no-project', `${skill}/scripts/requirements.py`])
    assert.equal(argv[argv.indexOf('--request') + 1], result.validation_request_path)
    assert.equal(result.validation_request.root, root)
    assert.deepEqual(result.validation_request.specifications, [specification])
    assert.equal(argv[argv.indexOf('--output') + 1], `${root}/.trailmark/specification-assurance/runs/run-12345678/gate.json`)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('large inventories travel in file data without growing the native command', async () => {
  const many = Array.from({ length: 5000 }, (_, i) => ({ ...requirements[0], id: i.toString(16).padStart(20, '0') }))
  const small = await run()
  const { error, result } = await run({ handlers: {
    setup: (_, { defaults }) => ({ ...defaults.setup(), requirements: many }),
  } })
  assert.equal(error, undefined)
  assert.equal(result.validation_request.requirements.length, many.length)
  assert.equal(Object.keys(result.validation_request.assessments).length, many.length)
  assert.equal(result.validation_command, small.result.validation_command)
})

test('JSON argument strings are accepted', async () => {
  const { error } = await run({ input: JSON.stringify({ target: '.', specifications: ['spec.md'], skill_dir: SKILL }) })
  assert.equal(error, undefined)
})
