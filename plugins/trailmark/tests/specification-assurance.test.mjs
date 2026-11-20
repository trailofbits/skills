// Workflow accounting tests; real Duvet evidence is exercised separately.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../workflows/specification-assurance.js', import.meta.url), 'utf8')
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor
const workflow = new AsyncFunction('args', 'agent', 'phase', 'log', 'Date', 'Math', source.replace('export const meta', 'const meta'))
class FixedDate extends Date {
  constructor() { super('2026-11-17T22:00:00.000Z') }
}
const fixedMath = Object.create(Math)
fixedMath.random = () => 0.25
const ROOT = '/workspace/project'
const RUN = `${ROOT}/.trailmark/specification-assurance/runs/20261117T220000000Z-9`
const SKILL = '/plugins/trailmark/skills/specification-assurance'
const requirements = ['a'.repeat(20), 'b'.repeat(20)].map((id) => ({
  id, specification: 'spec.md', section: 'packets', level: 'MUST', quote: 'Packets MUST be bounded.',
}))

async function run({ input = { specifications: ['spec.md'] }, handlers = {} } = {}) {
  const calls = []
  const phases = []
  const defaults = {
    resolve: () => ({ target: ROOT, skill_dir: SKILL, reason: '' }),
    setup: () => ({ status: 'ready', reason: '', source_files: 3, requirements, limitations: [] }),
    assess: (id) => ({ id, record_path: `${RUN}/requirements/${id}.json` }),
    report: () => ({
      duvet_ok: true, report_path: `${RUN}/report.md`, ledger_path: `${RUN}/ledger.json`, gate_path: `${RUN}/gate.json`,
      gate: { valid: true, status: 'supported', total: 2, verdicts: { supported: 2 }, limitations: [], errors: [] },
    }),
  }
  const all = { ...defaults, ...handlers }
  const agent = async (prompt, options) => {
    calls.push(options.label)
    const [stage, id] = options.label.split(':')
    return all[stage](id, { prompt, defaults })
  }
  try {
    const result = await workflow(input, agent, (value) => phases.push(value), () => {}, FixedDate, fixedMath)
    return { result, calls, phases }
  } catch (error) {
    return { error, calls, phases }
  }
}

test('every original requirement is assessed and the exact report paths are returned', async () => {
  const { error, result, calls, phases } = await run()
  assert.equal(error, undefined)
  assert.deepEqual(calls, ['resolve', 'setup', ...requirements.map((r) => `assess:${r.id}`), 'report'])
  assert.deepEqual(phases, ['Setup', 'Assess', 'Report'])
  assert.equal(result.total, 2)
  assert.equal(result.report, `${RUN}/report.md`)
  assert.equal(result.status, 'supported')
})

test('malformed inputs fail before tools or target mutations', async () => {
  for (const input of [{}, 'scan everything', [], { specifications: [] }, { specifications: [42] },
    { specifications: ['spec.md'], target: 'a\nb' }, { specifications: ['spec.md'], skill_dir: 'relative' },
    { specifications: ['spec.md'], ignore_errors: true }]) {
    const { error, calls } = await run({ input })
    assert.ok(error, JSON.stringify(input))
    assert.deepEqual(calls, [])
  }
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

test('a failed assessment does not discard later requirements and can finish as gaps', async () => {
  const { error, result, calls } = await run({ handlers: {
    assess: (id, { defaults }) => {
      if (id === requirements[0].id) throw new Error('Native verifier unavailable')
      return defaults.assess(id)
    },
    report: (_, { defaults }) => {
      const result = defaults.report()
      result.gate.status = 'gaps'
      result.gate.verdicts = { not_checked: 1, supported: 1 }
      return result
    },
  } })
  assert.equal(error, undefined)
  assert.equal(result.status, 'gaps')
  assert.ok(calls.includes(`assess:${requirements[1].id}`))
})

test('failed workers cannot be converted into an overall supported result', async () => {
  const { error, calls } = await run({ handlers: { assess: () => { throw new Error('No tool') } } })
  assert.match(error.message, /Unassessed/)
  assert.equal(calls.at(-1), 'report')
})

test('non-Error worker failures retain their reason and do not stop later assessments', async () => {
  const { error, result } = await run({ handlers: {
    assess: (id, { defaults }) => {
      if (id === requirements[0].id) throw null
      return defaults.assess(id)
    },
    report: (_, { prompt, defaults }) => {
      assert.ok(prompt.includes('"error": "null"'))
      const result = defaults.report()
      result.gate.status = 'gaps'
      result.gate.verdicts = { not_checked: 1, supported: 1 }
      return result
    },
  } })
  assert.equal(error, undefined)
  assert.equal(result.status, 'gaps')
})

test('unknown verdicts, gate errors, empty limitations, and wholly inapplicable scopes are invalid', async () => {
  for (const update of [{ verdicts: { skipped: 2 } }, { errors: ['Missing source'] },
    { limitations: [''] }, { verdicts: { not_applicable: 2 } }]) {
    const { error } = await run({ handlers: {
      report: (_, { defaults }) => {
        const result = defaults.report()
        Object.assign(result.gate, update)
        return result
      },
    } })
    assert.ok(error, JSON.stringify(update))
  }
})

test('final native failure, invalid accounting, and a shrunk denominator cannot pass', async () => {
  for (const update of [{ duvet_ok: false }, { gate_path: '/old/gate.json' },
    { gate: { valid: false, status: 'invalid', total: 2 } },
    { gate: { valid: true, status: 'supported', total: 1, verdicts: { supported: 1 } } },
    { gate: { valid: true, status: 'supported', total: 2, verdicts: { supported: 1 } } }]) {
    const { error } = await run({ handlers: {
      report: (_, { defaults }) => ({ ...defaults.report(), ...update }),
    } })
    assert.ok(error)
  }
})

test('JSON argument strings are accepted', async () => {
  const { error } = await run({ input: '{"target":".","specifications":["spec.md"]}' })
  assert.equal(error, undefined)
})

test('setup limitations survive into the final gate', async () => {
  const { error } = await run({ handlers: {
    setup: (_, { defaults }) => ({ ...defaults.setup(), limitations: ['Unsupported formal source'] }),
  } })
  assert.match(error.message, /limitations were lost/)
})
