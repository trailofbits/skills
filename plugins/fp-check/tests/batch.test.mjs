/**
 * Layer 2: triage-batch.js — the pure gates in isolation, then the whole script
 * against scripted sub-workflows.
 *
 * The two capabilities this workflow exists for are false-NEGATIVE guards, which
 * is what makes them worth this much test: a finding that is silently dropped and
 * a pair that is never compared both look exactly like a clean run. Neither shows
 * up as a wrong answer anywhere, so nothing but an assertion on the ledger and on
 * the pairing can see them.
 *
 * Every table here is a table rather than one example, per AGENTS.md: the two
 * functions in this plugin that regressed five consecutive times were each
 * validated against a handful of strings.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const SCRIPT = script('triage-batch.js')
const BASE = '/plugin/skills/fp-check'

// --------------------------------------------------------------- fixtures

const finding = {
  summary: 'an unvalidated upstream rate reaches ledger.debit',
  sink: 'billing/charge.py:44',
  component: 'billing',
  claimedImpact: 'an attacker mints balance',
  bugClass: 'input validation',
  threatModel: 'a network attacker who influences the rate service reaches charge()',
}
const entryPoint = {
  description: 'POST /orders',
  location: 'api/orders.py:12',
  payload: 'qty=125 with the rate service returning -1.00',
}

const entry = (id, over = {}) => ({
  id,
  finding: { ...finding, summary: `finding ${id}` },
  entryPoint,
  layers: [{ name: 'sign-check', location: 'billing/charge.py:40' }],
  ...over,
})

const args = (ids = ['a', 'b'], over = {}) => ({
  baseDir: BASE,
  scope: 'the billing service and the rate client it calls',
  findings: ids.map((id) => entry(id)),
  ...over,
})

const CONTEXT = {
  entryPoints: 'POST /orders reaches billing.charge through api/orders.py',
  trustBoundaries: 'api/mw.py authenticates every request before the router',
  framework: 'flask 3.0 on cpython 3.12',
  recoveryDefaults: 'werkzeug returns 500 and the worker survives',
  declaredScope: 'SECURITY.md covers the billing service',
  evidence: 'api/mw.py, billing/charge.py',
}

const stopped = (name) => ({
  layer: name,
  location: `billing/${name}.py:10`,
  verdict: 'PAYLOAD_STOPPED_HERE',
  evidence: 'the payload is rejected here',
})
const blockedAt = (...names) => ({
  status: 'NOT_EXPLOITABLE',
  reason: `blocked at ${names.join(', ')}`,
  layers: names.map(stopped),
})
const CONFIRMED = { status: 'TRUE_POSITIVE', reason: 'the rate reaches ledger.debit', severity: 'High', layers: [] }
// The single likeliest way a Stage 1 child declines. BLOCKED is this codebase's
// own word for an analysis that did not RUN — triage-static.js returns it from
// nine sites, most of them a dead agent — and the ledger filed it as a verdict.
const BLOCKED_CHILD = { status: 'BLOCKED', reason: '2 layer agent(s) returned nothing; Stage 1c is unverified' }

const CHAIN_CONFIRMED = {
  chains: true,
  firstContribution: 'supplies an authenticated session for any tenant',
  secondContribution: 'accepts a negative rate once past the authz layer',
  supplies: 'the first defeats the authz check the second is blocked by',
  impact: 'balance is minted against another tenant',
  evidence: 'billing/authz.py:10 and billing/charge.py:44',
}
const NO_CHAIN = {
  chains: false,
  firstContribution: 'nothing',
  secondContribution: 'nothing',
  supplies: '',
  evidence: 'the two are unrelated code paths',
}

const labels = (r) => r.calls.map((c) => c.label)
const chainLabels = (r) => labels(r).filter((l) => l.startsWith('chain:'))
const staticAlways = () => blockedAt('authz')

// ================================================================ missingArgs

test('missingArgs: the batch shape, one row per way a dispatch goes wrong', () => {
  // `auditedSearch` alongside it: the layers rule reads through that sibling.
  const { missingArgs } = loadFns(SCRIPT, 'missingArgs', 'auditedSearch')
  const ok = args()

  const cases = [
    ['a well-formed two-finding batch', ok, []],
    ['no args at all', undefined, ['baseDir', 'scope', 'findings']],
    ['baseDir pointing at the target repo', { ...ok, baseDir: '/work/repo' }, ['baseDir']],
    ['baseDir with a trailing slash is accepted', { ...ok, baseDir: `${BASE}/` }, []],
    ['a relative baseDir', { ...ok, baseDir: 'skills/fp-check' }, ['baseDir']],
    ['a blank scope', { ...ok, scope: '   ' }, ['scope']],
    ['scope as an object', { ...ok, scope: { in: 'billing' } }, ['scope']],
    ['findings absent', { ...ok, findings: undefined }, ['findings']],
    ['findings empty', { ...ok, findings: [] }, ['findings']],
    ['findings not an array', { ...ok, findings: { a: entry('a') } }, ['findings']],
    ['six findings against a cap of five', { ...ok, findings: ['a', 'b', 'c', 'd', 'e', 'f'].map((i) => entry(i)) }, ['findings']],
    ['an entry with no id', { ...ok, findings: [entry('a'), { ...entry('b'), id: undefined }] }, ['findings[1].id']],
    ['two entries sharing an id', { ...ok, findings: [entry('a'), entry('a')] }, ['findings[1].id']],
    ['an entry missing a finding field', { ...ok, findings: [entry('a'), { ...entry('b'), finding: { ...finding, threatModel: '' } }] }, ['findings[1].finding.threatModel']],
    ['an entry with no entryPoint at all', { ...ok, findings: [{ ...entry('a'), entryPoint: undefined }] }, ['findings[0].entryPoint.description', 'findings[0].entryPoint.location', 'findings[0].entryPoint.payload']],
    ['an entry that is not an object', { ...ok, findings: ['a bug in billing'] }, ['findings[0]']],
    ['empty layers with no layersSearched', { ...ok, findings: [{ ...entry('a'), layers: [] }] }, ['findings[0].layers']],
    // A stand-in is not a declaration: it cleared the old non-blankness rule and
    // the entry was forwarded to Stage 1, which then reached a verdict on zero
    // layer agents.
    ['empty layers with a stand-in for layersSearched', { ...ok, findings: [{ ...entry('a'), layers: [], layersSearched: 'n/a' }] }, ['findings[0].layers']],
    ['empty layers WITH layersSearched', { ...ok, findings: [{ ...entry('a'), layers: [], layersSearched: 'read api/orders.py and billing/charge.py; no validation between them' }] }, []],
    ['a layer with no location', { ...ok, findings: [{ ...entry('a'), layers: [{ name: 'sign-check' }] }] }, ['findings[0].layers[0].location']],
    ['layers as a string', { ...ok, findings: [{ ...entry('a'), layers: 'the sign check' }] }, ['findings[0].layers']],
  ]

  for (const [name, input, expected] of cases) {
    const got = missingArgs(input, 5)
    for (const want of expected) {
      assert.ok(
        got.some((m) => m.startsWith(want)),
        `${name}: expected a complaint about '${want}', got ${JSON.stringify(got)}`,
      )
    }
    if (expected.length === 0) assert.deepEqual(got, [], `${name}: expected no complaint`)
  }
})

test('missingArgs: an empty batch is rejected rather than returning a clean empty ledger', () => {
  // The zero-item guard, called out on its own because it is the failure this
  // codebase keeps rediscovering — `layers`, `sources`, the citation gate. Every
  // loop below matches nothing on an empty list, so without this the script
  // reports a batch triaged having triaged nothing.
  // `auditedSearch` alongside it: the layers rule reads through that sibling.
  const { missingArgs } = loadFns(SCRIPT, 'missingArgs', 'auditedSearch')
  assert.ok(missingArgs({ ...args(), findings: [] }, 5).some((m) => m.startsWith('findings')))
})

// ============================================================ accountFindings

test('accountFindings: every dispatched finding lands in exactly one column', () => {
  const accountFindings = loadFn(SCRIPT, 'accountFindings')
  const entries = [entry('a'), entry('b'), entry('c')]

  const cases = [
    [
      'all three returned a verdict',
      [CONFIRMED, blockedAt('authz'), CONFIRMED],
      ['a', 'b', 'c'],
      [],
    ],
    [
      'the middle sub-workflow returned null',
      [CONFIRMED, null, CONFIRMED],
      ['a', 'c'],
      ['b'],
    ],
    [
      'a sub-workflow returned a payload with no status',
      [CONFIRMED, { reason: 'something happened', layers: [] }, CONFIRMED],
      ['a', 'c'],
      ['b'],
    ],
    [
      'a status of whitespace is not a status',
      [{ status: '   ', reason: 'x' }, CONFIRMED, CONFIRMED],
      ['b', 'c'],
      ['a'],
    ],
    [
      'fewer results than dispatches: the tail was never dispatched',
      [CONFIRMED],
      ['a'],
      ['b', 'c'],
    ],
    ['nothing came back at all', [null, null, null], [], ['a', 'b', 'c']],
    [
      'a sub-workflow that could not run at all',
      [CONFIRMED, BLOCKED_CHILD, CONFIRMED],
      ['a', 'c'],
      ['b'],
    ],
    ['every sub-workflow BLOCKED', [BLOCKED_CHILD, BLOCKED_CHILD, BLOCKED_CHILD], [], ['a', 'b', 'c']],
    [
      'a status this script does not recognise',
      [{ status: 'TRIAGED', reason: 'stage 2 finished' }, CONFIRMED, CONFIRMED],
      ['b', 'c'],
      ['a'],
    ],
    [
      'the internal PROCEED sentinel escaping decideGate',
      [{ status: 'PROCEED', reason: '' }, CONFIRMED, CONFIRMED],
      ['b', 'c'],
      ['a'],
    ],
    [
      'a verdict in the wrong case',
      [{ status: 'true_positive', reason: 'x' }, CONFIRMED, CONFIRMED],
      ['b', 'c'],
      ['a'],
    ],
  ]

  for (const [name, results, verified, unverified] of cases) {
    const got = accountFindings(entries, results)
    assert.equal(got.problem, '', `${name}: unexpected problem ${got.problem}`)
    assert.deepEqual(got.verified.map((v) => v.id), verified, name)
    assert.deepEqual(got.unverified.map((u) => u.id), unverified, name)
    assert.equal(
      got.verified.length + got.unverified.length,
      entries.length,
      `${name}: a dispatched finding is in neither column`,
    )
    for (const row of got.unverified) assert.ok(row.why.trim() !== '', `${name}: an unverified row with no reason`)
  }
})

// Both directions in one table, so it fails if BLOCKED is accepted AND if a real
// verdict is rejected. The allowlist is pinned to triage-static.js's own status
// literals by test_the_batch_verdict_allowlist_matches_what_stage_1_returns.
test('accountFindings: every status Stage 1 returns is graded, and BLOCKED is not a verdict', () => {
  const accountFindings = loadFn(SCRIPT, 'accountFindings')
  const cases = [
    ['TRUE_POSITIVE', true],
    ['FALSE_POSITIVE', true],
    ['NOT_EXPLOITABLE', true],
    ['NOT_VULNERABLE', true],
    ['NEEDS_MORE_INFO', true],
    ['ALREADY_FIXED', true],
    ['OUT_OF_SCOPE', true],
    ['BLOCKED', false],
  ]
  for (const [status, isVerdict] of cases) {
    const got = accountFindings([entry('a')], [{ status, reason: 'r' }])
    assert.equal(got.problem, '', status)
    assert.deepEqual(got.verified.map((v) => v.id), isVerdict ? ['a'] : [], status)
    assert.deepEqual(got.unverified.map((u) => u.id), isVerdict ? [] : ['a'], status)
  }
})

// An unverified row is the orchestrator's NEEDS MORE INFO and the missing fact is
// the deliverable; a row naming only an id is unactionable.
test('accountFindings: a BLOCKED row keeps the reason it was blocked for', () => {
  const accountFindings = loadFn(SCRIPT, 'accountFindings')
  const got = accountFindings([entry('a')], [BLOCKED_CHILD])
  assert.match(got.unverified[0].why, /BLOCKED/)
  assert.ok(got.unverified[0].why.includes(BLOCKED_CHILD.reason))
})

test('accountFindings: more results than dispatches is a hard stop, not a tally', () => {
  // The same precedence decideGate uses one level down: some result came from
  // something that is not a dispatched finding, so no row read out of either list
  // can be trusted — including a dismissal filed under the wrong finding's id.
  const accountFindings = loadFn(SCRIPT, 'accountFindings')
  const got = accountFindings([entry('a')], [CONFIRMED, CONFIRMED])
  assert.match(got.problem, /mis-attributed/)
  assert.deepEqual(got.verified, [])
})

test('accountFindings: the ledger tallies against the DISPATCH list, not the returns', () => {
  // The specific fail-open this function exists for. Tallying `results` would
  // report one of one verified for a batch of three, and the two lost findings
  // would appear nowhere at all.
  const accountFindings = loadFn(SCRIPT, 'accountFindings')
  const got = accountFindings([entry('a'), entry('b'), entry('c')], [CONFIRMED, null, null])
  assert.equal(got.verified.length + got.unverified.length, 3)
})

// ============================================================== contextBlock

test('contextBlock: absent and blank fields are dropped, never passed down as text', () => {
  const contextBlock = loadFn(SCRIPT, 'contextBlock')

  assert.equal(contextBlock(null), '', 'a dead context agent produces a block')
  assert.equal(contextBlock({}), '', 'an empty return produces a block')
  assert.equal(contextBlock({ framework: '   ' }), '', 'whitespace counts as established')

  const partial = contextBlock({ ...CONTEXT, declaredScope: '' })
  assert.ok(!/undefined/.test(partial), 'an absent field reached the block as the text undefined')
  assert.ok(!/Declared scope/.test(partial), 'a blank field kept its heading, which reads as established')
  assert.match(partial, /flask 3\.0/)

  const full = contextBlock(CONTEXT)
  for (const value of Object.values(CONTEXT)) {
    if (value === CONTEXT.evidence) continue
    assert.ok(full.includes(value), `the block dropped ${value}`)
  }
})

// ========================================================== chain candidates

test('pairReason: the pairing rule, one row per shape', () => {
  const { pairReason } = loadFns(SCRIPT, 'pairReason', 'blockingLayers')
  const row = (id, status, result) => ({ id, status, result })

  const ne = (name) => row('x', 'NOT_EXPLOITABLE', blockedAt(name))
  const cases = [
    ['two unexploitable behind DIFFERENT walls', ne('authz'), row('y', 'NOT_EXPLOITABLE', blockedAt('quota')), true],
    ['two unexploitable behind the SAME wall', ne('authz'), row('y', 'NOT_EXPLOITABLE', blockedAt('authz')), false],
    [
      'the same two walls, reported in a different order',
      row('x', 'NOT_EXPLOITABLE', blockedAt('authz', 'quota')),
      row('y', 'NOT_EXPLOITABLE', blockedAt('quota', 'authz')),
      false,
    ],
    ['overlapping but not identical walls', ne('authz'), row('y', 'NOT_EXPLOITABLE', blockedAt('authz', 'quota')), true],
    ['one names no blocking layer at all', ne('authz'), row('y', 'NOT_EXPLOITABLE', { status: 'NOT_EXPLOITABLE', layers: [] }), true],
    ['unexploitable plus confirmed', ne('authz'), row('y', 'TRUE_POSITIVE', CONFIRMED), true],
    ['confirmed plus unexploitable, the other way round', row('x', 'TRUE_POSITIVE', CONFIRMED), ne('authz'), true],
    ['needs-more-info plus confirmed', row('x', 'NEEDS_MORE_INFO', {}), row('y', 'TRUE_POSITIVE', CONFIRMED), true],
    ['two confirmed findings', row('x', 'TRUE_POSITIVE', CONFIRMED), row('y', 'TRUE_POSITIVE', CONFIRMED), false],
    // These two are absent by decision, not by oversight, and the reason is in
    // `pairReason`'s own comment: a NEEDS_MORE_INFO names its missing fact only in
    // prose, so either pair could only be selected on the status alone — the
    // string heuristic this plugin has regressed on five times — and both would
    // spend against a cap of 3 that is sliced in candidate order.
    ['two needs-more-info', row('x', 'NEEDS_MORE_INFO', {}), row('y', 'NEEDS_MORE_INFO', {}), false],
    ['needs-more-info plus unexploitable', row('x', 'NEEDS_MORE_INFO', {}), ne('authz'), false],
  ]

  for (const [name, a, b, paired] of cases) {
    const why = pairReason(a, b)
    assert.equal(why !== '', paired, `${name}: got ${JSON.stringify(why)}`)
    if (paired) assert.ok(why.trim() !== '', `${name}: paired with an empty reason`)
  }
})

test('isChainable: a dead or dismissed finding is not a chain primitive', () => {
  const isChainable = loadFn(SCRIPT, 'isChainable')
  const table = [
    ['NOT_EXPLOITABLE', true],
    ['TRUE_POSITIVE', true],
    ['NEEDS_MORE_INFO', true],
    // Dead, and pairing it invites the chain agent to argue it back to life.
    ['ALREADY_FIXED', false],
    ['NOT_VULNERABLE', false],
    ['OUT_OF_SCOPE', false],
    ['FALSE_POSITIVE', false],
    ['BLOCKED', false],
    ['', false],
    ['true_positive', false],
  ]
  for (const [status, want] of table) assert.equal(isChainable(status), want, status)
})

test('chainCandidates: pairs are unordered, unique, and never include a dead finding', () => {
  const { chainCandidates } = loadFns(SCRIPT, 'chainCandidates', 'pairReason', 'blockingLayers', 'isChainable')
  const row = (id, status, result) => ({ id, status, result })

  const four = [
    row('a', 'NOT_EXPLOITABLE', blockedAt('authz')),
    row('b', 'NOT_EXPLOITABLE', blockedAt('quota')),
    row('c', 'NOT_EXPLOITABLE', blockedAt('rate')),
    row('d', 'ALREADY_FIXED', { status: 'ALREADY_FIXED' }),
  ]
  const pairs = chainCandidates(four).map((p) => `${p.first.id}+${p.second.id}`)
  assert.deepEqual(pairs, ['a+b', 'a+c', 'b+c'], 'the pairing is not the unordered set of eligible findings')
  assert.ok(!pairs.some((p) => p.includes('d')), 'an ALREADY_FIXED finding was paired')

  assert.deepEqual(chainCandidates([]), [], 'an empty ledger produced pairs')
  assert.deepEqual(chainCandidates([four[0]]), [], 'one finding was paired with itself')
})

// =============================================================== chainProblem

test('chainProblem: a claimed chain must name both contributions and the mechanism', () => {
  const chainProblem = loadFn(SCRIPT, 'chainProblem')
  const cases = [
    ['a complete chain', CHAIN_CONFIRMED, ''],
    ['no chain claimed', NO_CHAIN, ''],
    ['a dead agent', null, 'nothing'],
    ['chains true with no mechanism', { ...CHAIN_CONFIRMED, supplies: '' }, 'supplies'],
    ['chains true with a whitespace mechanism', { ...CHAIN_CONFIRMED, supplies: '   ' }, 'supplies'],
    ['chains true with no first contribution', { ...CHAIN_CONFIRMED, firstContribution: '' }, 'firstContribution'],
    ['chains true with neither contribution', { ...CHAIN_CONFIRMED, firstContribution: '', secondContribution: '' }, 'firstContribution and secondContribution'],
    // "these two are both auth bugs", which is the wrong chain this gate is for.
    ['the same sentence for both findings', { ...CHAIN_CONFIRMED, secondContribution: CHAIN_CONFIRMED.firstContribution }, 'only one was named'],
    ['the same sentence in a different case', { ...CHAIN_CONFIRMED, secondContribution: CHAIN_CONFIRMED.firstContribution.toUpperCase() }, 'only one was named'],
    // `chains` absent is not `chains: false`; it is a schema violation, and the
    // gate must not read it as a claim either way.
    ['chains absent', { ...CHAIN_CONFIRMED, chains: undefined }, ''],
  ]
  for (const [name, verdict, expected] of cases) {
    const got = chainProblem(verdict)
    if (expected === '') assert.equal(got, '', name)
    else assert.ok(got.includes(expected), `${name}: expected a complaint mentioning '${expected}', got '${got}'`)
  }
})

// ==================================================================== wiring

test('wiring: the arg gate fires before a single agent is dispatched', async () => {
  const r = await runScript('triage-batch.js', { args: { ...args(), findings: [] }, agents: {} })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /findings/)
  assert.deepEqual(r.calls, [], 'the context agent was paid for on a dispatch that could not run')
  assert.deepEqual(r.workflowCalls, [], 'a sub-workflow was dispatched on an unusable arg shape')
})

test('wiring: each finding is dispatched to Stage 1 with its OWN args and the shared context', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: () => staticAlways(),
  })
  assert.equal(r.workflowCalls.length, 2)
  assert.deepEqual(r.workflowCalls.map((c) => c.name), ['fp-check:triage-static', 'fp-check:triage-static'])
  assert.deepEqual(r.workflowCalls.map((c) => c.args.finding.summary), ['finding a', 'finding b'])
  for (const call of r.workflowCalls) {
    assert.equal(call.args.baseDir, BASE)
    assert.equal(call.args.scope, args().scope, 'the batch scope did not reach the child')
    assert.match(call.args.context, /flask 3\.0/, 'the shared context did not reach the child')
    assert.ok(!/undefined/.test(call.args.context), 'the context block carried the text undefined')
  }
})

test('wiring: a dead context agent degrades the batch, it does not fail it', async () => {
  // The saving is worth having and is not worth the capability. Without the
  // shared context each child derives its own, which is exactly what a single
  // dispatch does today.
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: null, chain: NO_CHAIN },
    workflows: () => staticAlways(),
  })
  assert.equal(r.result.status, 'BATCH_TRIAGED')
  assert.equal(r.workflowCalls.length, 2, 'a dead context agent stopped the triage')
  for (const call of r.workflowCalls) assert.equal(call.args.context, '')
  assert.ok(r.logs.some((l) => /shared context could not be established/.test(l)))
})

test('wiring: a finding whose sub-workflow THREW is reported, not dropped', async () => {
  // The unscripted-name case is how the real runtime fails — `workflow()` throws
  // on an unknown name or a child syntax error, and `pipeline` turns that into a
  // null for that item only.
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => {
      if (sub.finding.summary === 'finding b') throw new Error('the child died')
      return staticAlways()
    },
  })
  assert.equal(r.result.status, 'BATCH_TRIAGED')
  assert.deepEqual(r.result.unverified.map((u) => u.id), ['b'])
  assert.deepEqual(r.result.findings.map((f) => f.id), ['a'])
})

test('wiring: a batch where nothing reached a verdict is BLOCKED, not BATCH_TRIAGED', async () => {
  // The last hiding place of the vacuous pass: a ledger of nothing but unverified
  // rows, returned under a status with TRIAGED in it.
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: () => null,
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /no finding reached a verdict/)
  assert.deepEqual(r.result.unverified.map((u) => u.id), ['a', 'b'])
  assert.deepEqual(chainLabels(r), [], 'chains were checked over an empty ledger')
})

// The same hiding place, entered by the door the null-child test above does not
// cover: every child returned BLOCKED. `status` was non-blank, so the ledger
// counted three verdicts, the guard could not fire, and the batch came back
// BATCH_TRIAGED / "3 of 3 finding(s) verified; 0 unverified" over three analyses
// that never ran. Grading a guard on one of its two inputs is why this slipped.
test('wiring: a batch where every child BLOCKED is BLOCKED, not "N of N verified"', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b', 'c']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: () => BLOCKED_CHILD,
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /no finding reached a verdict/)
  assert.match(r.result.reason, /Stage 1c is unverified/, "the child's own reason has to reach the caller")
  assert.deepEqual(r.result.unverified.map((u) => u.id), ['a', 'b', 'c'])
  assert.deepEqual(r.result.findings, [])
  assert.ok(!r.logs.some((l) => /reached a verdict\./.test(l)), 'nothing reached a verdict, so nothing may say so')
  assert.deepEqual(chainLabels(r), [])
})

// The correct-behaviour direction, so the fix files BLOCKED elsewhere rather than
// dropping it: a blocked finding is still reported, beside the ones that decided,
// through the channel SKILL.md says must not be omitted.
test('wiring: a BLOCKED child is reported beside the findings that DID reach a verdict', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => (sub.finding.summary === 'finding a' ? BLOCKED_CHILD : CONFIRMED),
  })
  assert.equal(r.result.status, 'BATCH_TRIAGED')
  assert.deepEqual(r.result.findings.map((f) => [f.id, f.status]), [['b', 'TRUE_POSITIVE']])
  assert.deepEqual(r.result.unverified.map((u) => u.id), ['a'])
  assert.match(r.result.reason, /1 of 2 finding\(s\) verified; 1 unverified/)
  assert.ok(r.logs.some((l) => /UNVERIFIED a/.test(l)))
  assert.deepEqual(r.result.notChainable, [], 'a blocked finding is not a verdict that merely cannot chain')
})

test('wiring: the chain verdict reaches the return, with both contributions', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: CHAIN_CONFIRMED },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.deepEqual(chainLabels(r), ['chain:a+b'])
  assert.equal(r.result.chains.length, 1)
  assert.deepEqual(r.result.chains[0].findings, ['a', 'b'])
  assert.equal(r.result.chains[0].supplies, CHAIN_CONFIRMED.supplies)
  assert.match(r.result.reason, /1 chain\(s\) confirmed/)
})

// ===================================================== what the chain agent sees
//
// Nothing asserted on the chain prompt's CONTENT before these: the fan-out was
// tested for its labels, its cap and its rejection logic, never for what it says.
// So the only false-negative guard in the plugin was shown a status and a
// sentence — `blocked at <layer>` on the canonical pair — and told to answer
// chains:false whenever it could not name the supplying mechanism.

test('describe: the chain agent is told what each finding IS, not only its status', () => {
  const describe = loadFn(SCRIPT, 'describe')
  const row = { id: 'a', status: 'NOT_EXPLOITABLE', reason: 'blocked at authz (billing/authz.py:10)', finding, entryPoint }
  const text = describe(row)

  assert.match(text, /^a — NOT_EXPLOITABLE: blocked at authz \(billing\/authz\.py:10\)/, 'the verdict line changed')
  for (const value of Object.values(finding)) {
    assert.ok(text.includes(value), `the description dropped ${value}`)
  }
  for (const value of Object.values(entryPoint)) {
    assert.ok(text.includes(value), `the description dropped ${value}`)
  }
  // The claim is the submitter's and this phase never established it; an
  // unlabelled claimed impact reads to the agent as a fact.
  assert.match(text, /claimed impact, UNVERIFIED/)

  // Blank fields are dropped rather than rendered, for the reason contextBlock
  // drops them: a literal 'undefined' in a prompt reads as an established fact.
  const sparse = describe({ id: 'b', status: 'TRUE_POSITIVE', finding: { summary: 'only a summary' }, entryPoint: {} })
  assert.ok(!/undefined/.test(sparse), 'an absent field reached the prompt as the text undefined')
  assert.ok(!/sink:/.test(sparse), 'a blank field kept its label, which reads as established')
  assert.match(sparse, /no reason given/)
  assert.doesNotThrow(() => describe({ id: 'c', status: 'NEEDS_MORE_INFO' }), 'a row with no dispatch attached threw')
})

test('wiring: the chain prompt names both findings, out of the dispatch not the verdict', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  const prompt = r.calls.find((c) => c.label.startsWith('chain:')).prompt
  assert.ok(prompt.includes('finding a') && prompt.includes('finding b'), 'a finding was not named')
  // Exactly twice is what proves BOTH findings were described rather than one:
  // the two entries share these fixture values.
  for (const value of [finding.sink, finding.bugClass, finding.threatModel, entryPoint.location, entryPoint.payload]) {
    assert.equal(prompt.split(value).length - 1, 2, `${value} appears once, so only one finding was described`)
  }
})

test('wiring: a confirmed chain carries a status the Verdicts table can map', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b']),
    agents: { context: CONTEXT, chain: CHAIN_CONFIRMED },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.equal(r.result.chains[0].status, 'NEEDS_MORE_INFO')
  assert.match(r.result.chains[0].reason, /Re-run Stage 1/)
  assert.ok(r.result.chains[0].reason.includes(CHAIN_CONFIRMED.supplies), 'the mechanism is the deliverable')
  assert.deepEqual(r.result.findings.map((f) => f.chainedInto), [['a + b'], ['a + b']])
  // The guard against the over-fix. Rewriting a sub-workflow's verdict in the
  // parent is the "argue the dismissal back to life" this phase's prompt forbids,
  // and those findings ARE unexploitable alone.
  assert.deepEqual(r.result.findings.map((f) => f.status), ['NOT_EXPLOITABLE', 'NOT_EXPLOITABLE'])
})

test('wiring: no chain leaves every row unmarked, so the marker means something', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.deepEqual(r.result.chains, [])
  for (const rowOut of r.result.findings) {
    assert.ok(!('chainedInto' in rowOut), `${rowOut.id} was marked on a run with no chain`)
  }
})

test('chainedInto: a row is marked by every confirmed chain that names it', () => {
  const chainedInto = loadFn(SCRIPT, 'chainedInto')
  const confirmed = [{ findings: ['a', 'b'] }, { findings: ['a', 'c'] }, { findings: ['b', 'c'] }]
  assert.deepEqual(chainedInto({ id: 'a' }, confirmed), ['a + b', 'a + c'])
  assert.deepEqual(chainedInto({ id: 'd' }, confirmed), [])
  assert.deepEqual(chainedInto({ id: 'a' }, []), [])
  assert.deepEqual(chainedInto({ id: 'a' }, null), [])
})

test('wiring: a chain claimed without a mechanism is rejected and said out loud', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: { ...CHAIN_CONFIRMED, supplies: '' } },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.deepEqual(r.result.chains, [], 'a chain with no mechanism was reported')
  assert.ok(r.logs.some((l) => /rejected/.test(l)), 'the rejection was silent')
})

test('wiring: a dead chain agent leaves the pair UNCHECKED, not chain-free', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: null },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.deepEqual(r.result.chains, [])
  assert.deepEqual(r.result.chainsUnchecked, ['a + b'], 'a pair nobody checked was reported as no chain')
})

test('wiring: pairs beyond the cap are named as unchecked rather than dropped', async () => {
  // Four unexploitable findings behind four different walls is six pairs against
  // a cap of three. A silent cap reads as "every pair was checked", which is the
  // mistake triage-online now carries `beyondCap` for.
  const walls = { 'finding a': 'authz', 'finding b': 'quota', 'finding c': 'rate', 'finding d': 'tenant' }
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b', 'c', 'd']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => blockedAt(walls[sub.finding.summary]),
  })
  assert.equal(r.result.chainCandidates.length, 6)
  assert.equal(chainLabels(r).length, 3, 'the chain fan-out is not bounded by MAX_CHAINS')
  assert.equal(r.result.chainsBeyondCap.length, 3)
  assert.ok(r.logs.some((l) => /beyond the cap/.test(l)))
})

test('wiring: a finding that cannot chain is named rather than quietly ignored', async () => {
  const r = await runScript('triage-batch.js', {
    args: args(['a', 'b']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) =>
      sub.finding.summary === 'finding a'
        ? { status: 'ALREADY_FIXED', reason: 'fixed by 9fce2b1', layers: [] }
        : blockedAt('quota'),
  })
  assert.deepEqual(r.result.notChainable, ['a (ALREADY_FIXED)'])
  assert.deepEqual(chainLabels(r), [], 'an ALREADY_FIXED finding was paired')
  assert.deepEqual(r.result.findings.map((f) => f.status), ['ALREADY_FIXED', 'NOT_EXPLOITABLE'])
})

test('wiring: the phases run in order, and only Chains is a barrier', async () => {
  // The barrier placement is the design decision this script is built on, and it
  // is invisible from any result: `parallel` and `pipeline` return the same
  // shape. Triage must be a pipeline — finding B's Stage 1 starts as soon as A's
  // does, because there is no cross-finding decision until the chain phase — and
  // Chains must be a barrier, because the pairing genuinely needs every verdict.
  const r = await runScript('triage-batch.js', {
    args: args(),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: () => staticAlways(),
  })
  assert.deepEqual(r.phases, ['Context', 'Triage', 'Chains'])

  const src = readFileSync(SCRIPT, 'utf8')
  assert.match(src, /await pipeline\(findings\.slice\(0, MAX_FINDINGS\)/, 'the triage fan-out is no longer a capped pipeline')
  assert.match(src, /await parallel\(\s*\n?\s*candidates\.slice\(0, MAX_CHAINS\)/, 'the chain fan-out is no longer a capped barrier')
})
