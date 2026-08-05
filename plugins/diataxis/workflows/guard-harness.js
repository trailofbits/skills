#!/usr/bin/env node
// Exercises document.js against stubbed workflow hooks and asserts that each
// guard fires on the input it exists to catch.
//
// The guards are the whole correctness story of this workflow: without them a
// failed clone, a dead survey agent, or a writer that produced nothing all
// yield a run that reports success and ships an empty docs tree. A harness
// that asserted nothing would be worse than none, so this one fails when it
// runs fewer scenarios than it declares, and `guards.bats` separately proves
// it still fails when a guard is deleted.
//
// Usage: node guard-harness.js [--script <path-to-document.js>]

'use strict'

const fs = require('fs')
const path = require('path')
const vm = require('vm')

const argv = process.argv.slice(2)
const scriptIdx = argv.indexOf('--script')
const SCRIPT_PATH =
  scriptIdx === -1 ? path.join(__dirname, 'document.js') : argv[scriptIdx + 1]

const SRC = fs.readFileSync(SCRIPT_PATH, 'utf8').replace('export const meta', 'const meta')

const QUADRANTS = ['tutorial', 'how-to', 'reference', 'explanation']

function framework(overrides) {
  return Object.assign(
    {
      sourceCommit: 'f'.repeat(40),
      rstFilesRead: 10,
      readBrief: true,
      quadrants: QUADRANTS.map(name => ({
        name,
        userNeed: 'need',
        purpose: 'purpose',
        form: 'form',
        voice: 'voice',
        antiPatterns: ['anti'],
        acceptanceChecks: ['check'],
      })),
      compass: ['rule one', 'rule two'],
      qualityChecks: ['quality'],
    },
    overrides || {},
  )
}

function inventory(overrides) {
  return Object.assign(
    { languages: [{ name: 'Python' }], sourceFileCount: 42, existingDocs: [], conventions: {} },
    overrides || {},
  )
}

function manifest(label) {
  const m = { filesWritten: ['docs/page.md'], filesIntegrated: [], redirected: [], gaps: [] }
  if (label === 'author:reference') {
    m.generator = 'Sphinx'
    m.buildCommand = 'sphinx-build -b html docs docs/_build'
    m.symbolsDocumented = 10
    m.symbolsTotal = 12
    m.sourceFilesEdited = ['src/mod.py']
  }
  return m
}

const EMPTY_MANIFEST = { filesWritten: [], filesIntegrated: [], redirected: [], gaps: [] }

async function run(opts) {
  const calls = []
  const logs = []
  const override = opts.override || {}

  const agent = async (prompt, o) => {
    calls.push({ label: o.label, phase: o.phase, schema: !!o.schema, prompt: prompt })
    if (Object.prototype.hasOwnProperty.call(override, o.label)) {
      const v = override[o.label]
      if (v === 'throw') throw new Error('simulated agent failure')
      return v
    }
    if (o.label === 'framework:distill') {
      return Object.prototype.hasOwnProperty.call(opts, 'framework') ? opts.framework : framework()
    }
    if (o.label === 'survey:inventory') return inventory()
    if (o.label.startsWith('survey:')) return { ok: true }
    if (o.label.startsWith('author:')) return manifest(o.label)
    if (o.label === 'assemble:index') {
      return { indexPath: 'docs/index.md', summary: 'ok', brokenLinks: [], crossLinksAdded: 4 }
    }
    throw new Error('harness: unexpected agent label ' + o.label)
  }

  const parallel = async thunks => {
    const settled = await Promise.allSettled(thunks.map(t => t()))
    return settled.map(s => (s.status === 'fulfilled' ? s.value : null))
  }

  const sandbox = {
    args: Object.prototype.hasOwnProperty.call(opts, 'args')
      ? opts.args
      : { referencesDir: '/plugin/references', target: 'src', docsDir: 'docs' },
    agent: agent,
    parallel: parallel,
    phase: function () {},
    log: function (m) {
      logs.push(m)
    },
    JSON: JSON,
    Math: Math,
    Object: Object,
    Array: Array,
    Promise: Promise,
    Error: Error,
  }
  vm.createContext(sandbox)

  try {
    const fn = new vm.Script('(async()=>{' + SRC + '\n})', { filename: 'document.js' }).runInContext(
      sandbox,
    )
    return { threw: false, result: await fn(), calls: calls, logs: logs }
  } catch (e) {
    return { threw: true, error: e.message, calls: calls, logs: logs }
  }
}

// Each scenario names the guard it targets. `expect: 'throw'` means the run
// must abort; `expect: 'complete'` means it must finish and still report the
// degradation rather than hiding it.
const SCENARIOS = [
  {
    name: 'happy path runs 11 agents and reports no shortfall',
    opts: {},
    expect: 'complete',
    assert: r =>
      r.calls.length === 11 &&
      r.result.incomplete.surveyDimensionsFailed.length === 0 &&
      r.result.incomplete.quadrantsFailed.length === 0 &&
      r.result.incomplete.quadrantsEmpty.length === 0 &&
      r.result.reference.generator === 'Sphinx',
  },
  {
    name: 'missing referencesDir aborts before spawning anything',
    opts: { args: { target: '.' } },
    expect: 'throw',
    match: /referencesDir was not supplied/,
    assert: r => r.calls.length === 0,
  },
  {
    // Found by running the workflow for real: the caller passed args as a JSON
    // string, every field read as undefined, and the run aborted blaming a
    // missing referencesDir that had in fact been supplied.
    name: 'args passed as a JSON string is parsed, not rejected',
    opts: {
      args: JSON.stringify({ referencesDir: '/plugin/references', target: 'src', docsDir: 'docs' }),
    },
    expect: 'complete',
    assert: r =>
      r.calls.length === 11 &&
      r.calls.every(c => /\/plugin\/references\/agent-prompts\.md/.test(c.prompt)),
  },
  {
    name: 'args passed as unparseable string aborts with a useful message',
    opts: { args: 'target=src' },
    expect: 'throw',
    match: /args arrived as a string that is not JSON/,
  },
  {
    name: 'args passed as an array aborts',
    opts: { args: ['src'] },
    expect: 'throw',
    match: /args must be an object/,
  },
  {
    name: 'framework agent returning nothing aborts',
    opts: { framework: null },
    expect: 'throw',
    match: /returned nothing/,
  },
  {
    name: 'reported clone failure aborts',
    opts: { framework: framework({ cloneError: 'network unreachable' }) },
    expect: 'throw',
    match: /could not clone/,
  },
  {
    name: 'framework answered from memory (no commit SHA) aborts',
    opts: { framework: framework({ sourceCommit: '' }) },
    expect: 'throw',
    match: /no commit SHA/,
  },
  {
    name: 'short commit SHA aborts',
    opts: { framework: framework({ sourceCommit: 'abc' }) },
    expect: 'throw',
    match: /no commit SHA/,
  },
  {
    name: 'partial read of the framework source aborts',
    opts: { framework: framework({ rstFilesRead: 3 }) },
    expect: 'throw',
    match: /read only 3/,
  },
  {
    name: 'unreadable agent brief aborts',
    opts: { framework: framework({ readBrief: false }) },
    expect: 'throw',
    match: /could not read/,
  },
  {
    name: 'fewer than four quadrants aborts',
    opts: { framework: framework({ quadrants: framework().quadrants.slice(0, 3) }) },
    expect: 'throw',
    match: /expected 4 quadrant definitions/,
  },
  {
    name: 'four quadrants with a duplicate name aborts',
    opts: {
      framework: (() => {
        const f = framework()
        f.quadrants[3].name = 'tutorial'
        return f
      })(),
    },
    expect: 'throw',
    match: /missing quadrant/,
  },
  {
    name: 'inventory survey failure aborts',
    opts: { override: { 'survey:inventory': null } },
    expect: 'throw',
    match: /inventory survey failed/,
  },
  {
    name: 'zero source files aborts',
    opts: { override: { 'survey:inventory': inventory({ sourceFileCount: 0, languages: [] }) } },
    expect: 'throw',
    match: /0 source files/,
  },
  {
    name: 'one dead survey agent is tolerated but reported',
    opts: { override: { 'survey:architecture': 'throw' } },
    expect: 'complete',
    assert: r =>
      r.result.incomplete.surveyDimensionsFailed.length === 1 &&
      r.result.incomplete.surveyDimensionsFailed[0] === 'architecture' &&
      // the surviving writers must be told, or they fill the gap by inventing
      r.calls.some(c => c.label === 'author:explanation' && /UNAVAILABLE: architecture/.test(c.prompt)),
  },
  {
    name: 'three dead survey agents aborts',
    opts: {
      override: { 'survey:architecture': null, 'survey:operations': null, 'survey:onboarding': null },
    },
    expect: 'throw',
    match: /3 of 5 survey agents failed/,
  },
  {
    name: 'one empty quadrant is tolerated but reported',
    opts: { override: { 'author:explanation': EMPTY_MANIFEST } },
    expect: 'complete',
    assert: r =>
      r.result.incomplete.quadrantsEmpty.length === 1 &&
      r.result.incomplete.quadrantsEmpty[0] === 'explanation' &&
      // and the assembler must be told not to link it
      r.calls.some(c => c.label === 'assemble:index' && /produced NOTHING: explanation/.test(c.prompt)),
  },
  {
    name: 'all quadrants empty aborts',
    opts: {
      override: {
        'author:tutorials': EMPTY_MANIFEST,
        'author:how-to': EMPTY_MANIFEST,
        'author:reference': EMPTY_MANIFEST,
        'author:explanation': EMPTY_MANIFEST,
      },
    },
    expect: 'throw',
    match: /no quadrant produced any documentation/,
  },
  {
    name: 'reference written without a generator warns',
    opts: {
      override: {
        'author:reference': { filesWritten: ['docs/reference/index.md'], redirected: [], gaps: [] },
      },
    },
    expect: 'complete',
    assert: r => r.logs.some(l => /named no generator/.test(l)),
  },
  {
    name: 'assemble failure still returns the quadrant results',
    opts: { override: { 'assemble:index': null } },
    expect: 'complete',
    assert: r =>
      r.result.index === null &&
      r.logs.some(l => /assemble agent returned nothing/.test(l)) &&
      r.result.quadrants.filter(q => q.filesWritten.length).length === 4,
  },
  {
    name: 'every agent is given a schema and a phase',
    opts: {},
    expect: 'complete',
    assert: r => r.calls.every(c => c.schema === true && typeof c.phase === 'string' && c.phase),
  },
  {
    name: 'agent count stays under the medium size guideline of 15',
    opts: {},
    expect: 'complete',
    assert: r => r.calls.length < 15,
  },
]

// A harness that silently checked nothing would pass forever. Pin the count.
const EXPECTED_SCENARIOS = 23

async function main() {
  if (SCENARIOS.length < EXPECTED_SCENARIOS) {
    console.error(
      'FAIL: harness declares ' + EXPECTED_SCENARIOS + ' scenarios but only ' +
        SCENARIOS.length + ' are defined. Scenarios were removed without updating the count.',
    )
    process.exit(1)
  }

  let failed = 0
  for (const s of SCENARIOS) {
    const r = await run(s.opts)
    const problems = []

    if (s.expect === 'throw') {
      if (!r.threw) problems.push('expected the run to abort, but it completed')
      else if (s.match && !s.match.test(r.error)) {
        problems.push('aborted with the wrong error: ' + r.error.split('\n')[0])
      }
    } else {
      if (r.threw) problems.push('expected the run to complete, but it aborted: ' + r.error.split('\n')[0])
    }

    if (!problems.length && s.assert && !s.assert(r)) problems.push('assertion returned false')

    if (problems.length) {
      failed++
      console.error('FAIL: ' + s.name)
      for (const p of problems) console.error('      ' + p)
    } else {
      console.log('ok: ' + s.name)
    }
  }

  if (failed) {
    console.error('\n' + failed + ' of ' + SCENARIOS.length + ' guard scenarios failed')
    process.exit(1)
  }
  console.log('\nall ' + SCENARIOS.length + ' guard scenarios passed')
}

main().catch(e => {
  console.error('harness error: ' + (e && e.stack ? e.stack : e))
  process.exit(1)
})
