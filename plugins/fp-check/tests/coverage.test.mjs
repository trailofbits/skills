/**
 * Layer 2c: capability coverage — is each parent plugin's mechanism REACHABLE?
 *
 * fp-check 2.1.0 is a merge of three plugins. `gate.test.mjs` proves each pure
 * helper computes the right answer; `wiring.test.mjs` proves the helper's answer
 * is acted on. Neither answers the question this file exists for: **for every
 * distinct verification mechanism the merge inherited, does some realistic
 * dispatch actually route to it and let it decide?**
 *
 * That is a different failure mode from a wrong answer. A gate can be present,
 * correct and covered, and still never fire — because an earlier gate always
 * decides first, or because nothing in the merged plugin dispatches to it at
 * all. A measured sweep of 18 runs found `upstreamFixStands`, `capSeverity`,
 * `decideVerdict` and `severityCapViolation` with zero firings, and the brocard
 * pre-gate deciding 11 of 18. None of that shows up as a failing assertion
 * anywhere else in this suite.
 *
 * The rule for this file:
 *
 *   - A mechanism that SHOULD be reachable gets a dispatch that provably routes
 *     to it, and an assertion that it — not something upstream of it — decides.
 *   - A mechanism nobody can construct a dispatch for is UNREACHABLE, and the
 *     test FAILS LOUDLY rather than being omitted. An omitted test is how a
 *     capability that did not survive a merge stays invisible.
 *
 * Each test names its parent, so a red run says which plugin lost what.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { runScript, script } from './extract.mjs'

const BASE = '/plugin/skills/fp-check'

const STATIC_SRC = readFileSync(script('triage-static.js'), 'utf8')
const ONLINE_SRC = readFileSync(script('triage-online.js'), 'utf8')
const POC_SRC = readFileSync(script('triage-poc.js'), 'utf8')
const SKILL_SRC = readFileSync(
  new URL('../skills/fp-check/SKILL.md', import.meta.url),
  'utf8',
)

// --------------------------------------------------------------- fixtures
//
// One finding shape reused everywhere, so a test that changes the outcome has
// changed exactly one scripted agent answer and the cause is unambiguous.

const finding = {
  summary: 'an unvalidated upstream rate reaches ledger.debit',
  sink: 'billing/charge.py:44',
  component: 'billing',
  claimedImpact: 'an attacker mints balance',
  bugClass: 'input validation',
  threatModel: 'a network attacker who can influence the rate service reaches charge() and credits an account',
}
const entryPoint = {
  description: 'POST /orders',
  location: 'api/orders.py:12',
  payload: 'qty=125 with the rate service returning -1.00',
}

// A dispatch selectRoute must keep on the cheap path: one layer, a bug class
// that is on none of the escalation lists, no crossComponent/ambiguous signal.
const standardArgs = (over = {}) => ({
  baseDir: BASE,
  finding,
  entryPoint,
  scope: 'the billing service and the rate client it calls',
  layers: [{ name: 'sign-check', location: 'billing/charge.py:40' }],
  ...over,
})

const LAYER_PASSES = { verdict: 'PAYLOAD_REACHES_SINK', location: 'billing/charge.py:40', evidence: 'no sign check exists; the payload survives' }
const LAYER_BLOCKS = { verdict: 'PAYLOAD_STOPPED_HERE', location: 'billing/charge.py:40', evidence: 'rates below zero are rejected here' }
// A proof is not a layer and no longer shares its enum: a layer is asked what
// happens to the payload, a proof whether its own argument leaves the finding
// alive. These fixtures used to be LAYER_PASSES, which fed a layer verdict to a
// proof agent and read as correct because nothing validated the shape.
const PROOF_SURVIVES = { applies: true, verdict: 'FINDING_SURVIVES', evidence: 'this proof does not dispose of the finding' }
const RECOVERY = { recoveryExists: false, effectiveImpact: 'the balance is inflated', evidence: 'nothing recovers on this path' }
const THREAT_OK = { inScope: 'YES', byDesign: false, byDesignIndicators: 0, evidence: 'billing is named in the declared scope' }
const HISTORY_NONE = { fixed: 'NO', complete: false, reference: '', searched: 'git log -p billing/, CHANGELOG, issues', evidence: 'nothing found' }
const IMPACT_INTERNAL = {
  result: 'VERIFIED',
  impact: 'a negative rate credits the account instead of debiting it',
  rootCause: 'internal',
  classification: 'vulnerability',
  severity: 'High',
  severityRationale: 'direct, silent ledger corruption',
  evidence: 'traced from charge() to ledger.debit()',
}
const GATES_ALL_PASS = {
  gateProcess: 'PASS',
  gateReachability: 'PASS',
  gateRealImpact: 'PASS',
  gatePocValidation: 'PASS',
  gateMathBounds: 'N/A',
  gateEnvironment: 'PASS',
  unresolvedUncertainty: '',
  verdictReason: 'attacker-influenced data reaches ledger.debit unchecked',
  evidence: 'see the layer evidence',
}

const staticAgents = (over = {}) => ({
  layer: LAYER_PASSES,
  recovery: RECOVERY,
  'threat-model': THREAT_OK,
  history: HISTORY_NONE,
  impact: IMPACT_INTERNAL,
  gates: GATES_ALL_PASS,
  ...over,
})

// --- batch fixtures. `summary` carries the id so a scripted sub-workflow can
// tell the findings apart from the args it was handed, which is also the only
// evidence that each child got ITS finding rather than the first one repeatedly.
const batchArgs = (ids = ['a', 'b'], over = {}) => ({
  baseDir: BASE,
  scope: 'the billing service and the rate client it calls',
  findings: ids.map((id) => ({
    id,
    finding: { ...finding, summary: `finding ${id}` },
    entryPoint,
    layers: [{ name: 'sign-check', location: 'billing/charge.py:40' }],
  })),
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

// A Stage 1 return that is unexploitable and says WHERE, in the structured layer
// verdicts rather than only in the reason sentence — which is what pairReason
// compares.
const blockedAt = (name) => ({
  status: 'NOT_EXPLOITABLE',
  reason: `blocked at ${name} (billing/${name}.py:10)`,
  layers: [
    { layer: name, location: `billing/${name}.py:10`, verdict: 'PAYLOAD_STOPPED_HERE', evidence: 'the payload is rejected here' },
  ],
})

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
const promptFor = (r, label) => {
  const call = r.calls.find((c) => c.label === label)
  assert.ok(call, `no agent was dispatched with label '${label}'`)
  return call.prompt
}

// A helper that fails the test rather than returning, so an "unreachable"
// verdict cannot be mistaken for a skipped or pending test in the TAP output.
const unreachable = (parent, mechanism, why, wouldFix) => {
  assert.fail(
    `UNREACHABLE CAPABILITY — inherited from ${parent}\n` +
      `  mechanism: ${mechanism}\n` +
      `  why:       ${why}\n` +
      `  to fix:    ${wouldFix}\n` +
      '  This test is failing on purpose. Deleting it hides the gap; the merge\n' +
      '  claims this capability and no dispatch reaches it.',
  )
}

// ===================================================================
// concept-prover
// ===================================================================

test('[concept-prover] per-layer reachability: a blocking layer decides, before impact is spent', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ layer: LAYER_BLOCKS }),
  })
  assert.equal(r.result.status, 'NOT_EXPLOITABLE')
  assert.match(r.result.reason, /blocked at sign-check/)
  // The mechanism decided: the impact and gate agents were never reached, so
  // nothing downstream can be the thing that produced this status.
  assert.ok(!labels(r).includes('impact'), 'the impact agent ran, so the layer gate did not decide')
  assert.ok(!labels(r).includes('gates'), 'the gate agent ran, so the layer gate did not decide')
})

test('[concept-prover] per-layer reachability: one agent per enumerated layer, capped at 4', async () => {
  const four = [1, 2, 3, 4].map((i) => ({ name: `layer-${i}`, location: `f.py:${i}` }))
  const r = await runScript('triage-static.js', {
    args: standardArgs({ layers: four }),
    agents: staticAgents(),
  })
  const dispatched = labels(r).filter((l) => l.startsWith('layer:'))
  assert.equal(dispatched.length, 4, 'a layer must get its own agent; collapsing them is the mechanism the head-to-head measured')

  const five = [...four, { name: 'layer-5', location: 'f.py:5' }]
  const over = await runScript('triage-static.js', { args: standardArgs({ layers: five }), agents: staticAgents() })
  assert.equal(over.result.status, 'BLOCKED')
  assert.equal(labels(over).length, 0, 'the cap must reject before an agent is spent')
})

test('[concept-prover] the recovery check is a gate: a dead recovery agent blocks', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ recovery: null }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /recovery agent returned nothing/)
})

test('[concept-prover] the recovery finding reaches the impact agent, so it can downgrade', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      recovery: { recoveryExists: true, mechanism: 'net/http conn.serve', effectiveImpact: 'one connection closes', evidence: 'per-connection recover' },
    }),
  })
  assert.match(promptFor(r, 'impact'), /recovery EXISTS/)
  assert.match(promptFor(r, 'impact'), /one connection closes/)
})

test('[concept-prover] threat-model alignment decides scope and design intent', async () => {
  const out = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'NO', byDesign: false, byDesignIndicators: 0, evidence: 'billing is outside the declared scope' } }),
  })
  assert.equal(out.result.status, 'OUT_OF_SCOPE')
  assert.match(out.result.reason, /outside the declared scope/)

  const design = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'YES', byDesign: true, byDesignIndicators: 3, evidence: 'documented and covered by tests as normal operation' } }),
  })
  assert.equal(design.result.status, 'NOT_VULNERABLE')

  const ambiguous = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'UNCERTAIN', byDesign: false, byDesignIndicators: 0, evidence: 'the scope statement does not name billing' } }),
  })
  assert.equal(ambiguous.result.status, 'NEEDS_MORE_INFO')
})

// Raising the dismissal bar to two indicators routed the BELOW-bar signal
// nowhere: the impact prompt, the six-gate prompt and `decideVerdict` all went on
// never seeing `threat`, so a documented design-intent objection was dropped and
// the finding came back TRUE_POSITIVE with no record it had been raised. It is
// carried to the one agent holding all the other evidence — which is where a
// dismissal that was deferred rather than acted on has to be answered.
test('a by-design objection below the bar is carried to the six-gate agent', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      'threat-model': { inScope: 'YES', byDesign: true, byDesignIndicators: 1, evidence: 'the function is called forceUpdate' },
    }),
  })
  assert.equal(r.result.status, 'TRUE_POSITIVE', 'one indicator is a flag to check, not a dismissal')
  const gates = promptFor(r, 'gates')
  assert.match(gates, /forceUpdate/, 'the objection reaches the agent that can answer it')
  assert.match(gates, /1 of 3 design-intent indicators/)
})

// The other half of the same bar, and the stronger objection of the two: the bar
// is two indicators AND a confirming search, so an agent that obeys the prompt
// with three indicators and an unfinished search returns `byDesign: false`.
// Keyed on the boolean, that shape reached NO prompt in the file at all, while
// the one-indicator hunch above was carried.
test('a by-design objection with the indicators but not the boolean is carried too', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      'threat-model': {
        inScope: 'YES',
        byDesign: false,
        byDesignIndicators: 3,
        evidence: 'forceUpdate, a guarded withdraw() sibling, and test_admin_override covers it',
      },
    }),
  })
  assert.equal(r.result.status, 'TRUE_POSITIVE', 'below the bar is still not a dismissal')
  const gates = promptFor(r, 'gates')
  assert.match(gates, /3 of 3 design-intent indicators/)
  assert.match(gates, /forceUpdate/)
  assert.match(gates, /did not itself mark the finding by-design/)
})

// `type` is advisory to the runtime validator just as `enum` is, so the count
// arrives as whatever the agent typed.
test('an off-type indicator count still carries the objection', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      'threat-model': { inScope: 'YES', byDesign: false, byDesignIndicators: '2', evidence: 'two documented escape hatches' },
    }),
  })
  assert.equal(r.result.status, 'TRUE_POSITIVE')
  assert.match(promptFor(r, 'gates'), /2 of 3 design-intent indicators/)
})

// The guard on the fix rather than on the bug: carrying is not free. Without
// this, "always interpolate `threat`" would pass the two tests above and ask the
// verdict agent to answer an objection nobody raised, on every run.
test('no design-intent objection is carried when no indicator fired', async () => {
  const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.equal(r.result.status, 'TRUE_POSITIVE')
  assert.doesNotMatch(promptFor(r, 'gates'), /design-intent indicators/)
})

test('[concept-prover] the external-precondition rule decides an integration finding', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      impact: { ...IMPACT_INTERNAL, rootCause: 'integration', externalPrecondition: '   ' },
    }),
  })
  assert.equal(r.result.status, 'NEEDS_MORE_INFO')
  assert.match(r.result.reason, /external precondition/)
  assert.ok(!labels(r).includes('gates'), 'the gate agent ran, so 2.4b did not decide')
})

test('[concept-prover] the severity cap decides on the cheap path, and is reported', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service returns a negative rate' },
    }),
  })
  assert.equal(r.result.severity, 'Medium', 'capSeverity did not decide the severity the workflow returns')
  assert.match(r.result.severityCorrection, /lowered from Critical to Medium/)
  // And the CAPPED number, not the agent's claim, is what the gate agent sees.
  assert.match(promptFor(r, 'gates'), /Severity after the caps: Medium/)
})

// The traced shape of the 2.3.0 probe, end to end. `integration-cap`'s fixture has
// NO validation anywhere between fetch_rate and ledger.debit, and until 2.4.0 the
// dispatch contract told the orchestrator to send that absence as a layer. It did.
// An agent was then asked whether a layer that does not exist stops the payload,
// answered with the stopping verdict, and explained in `reason` that it meant the
// opposite. `decideGate` read the label, returned NOT_EXPLOITABLE before the impact
// agent, and `capSeverity` did not run — 0 firings in 64 measured runs. The
// orchestrator discarded the workflow and reported its own uncapped Critical.
//
// So this asserts the whole chain the probe found broken: an audited empty
// `layers` reaches the impact agent, and the cap decides.
test('[concept-prover] a path with NO validation reaches the impact agent, and the cap still decides', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs({
      layers: [],
      layersSearched:
        'read billing/charge.py, client/rates.py and billing/ledger.py end to end; no sign, bounds or type check on the rate between fetch_rate and debit',
    }),
    agents: staticAgents({
      impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service returns a negative rate' },
    }),
  })
  assert.ok(!labels(r).some((l) => l.startsWith('layer:')), 'a layer agent was dispatched for a path with no layers')
  assert.ok(labels(r).includes('impact'), 'the impact agent was never reached, so the severity cap cannot have run')
  assert.equal(r.result.severity, 'Medium', 'capSeverity did not decide: this is the 3-point loss integration-cap measures')
  assert.match(r.result.severityCorrection, /lowered from Critical to Medium/)
  // The impact and verdict agents must be told this was a caller's declaration and
  // not a verified fan-out. "All 0 validation layers were independently verified as
  // passable" is the vacuous pass arriving by the prompt instead of by the gate.
  assert.match(promptFor(r, 'impact'), /NO validation layer stands between/)
  assert.match(promptFor(r, 'impact'), /declared this rather than any agent verifying it/)
})

// The conflict two sweeps measured, and the assertion that bounds its fix.
//
// `rootCause: integration` means the trigger originates OUTSIDE the repository by
// construction. `gateReachability` as prompted demanded it be traced INSIDE it, so
// every integration finding failed the six-gate review on principle — and the
// Medium that `capSeverity` had already produced was discarded into a
// FALSE_POSITIVE. Traced twice: once with a brocard feeding the gate agent an
// unanswerable question, and again on sweep251 run1 with a correct baseDir, no
// brocards, and the gate agent writing "nothing in the code shown demonstrates an
// external actor driving the rate".
//
// The fix is a prohibition in the gate prompt, and the SECOND half of this test is
// the load-bearing one: it is the code-side proof that the relaxation is scoped to
// non-internal root causes. An unconditional prohibition would weaken the gate for
// every finding, including the internal ones where all the measured evidence lives.
test('[concept-prover] the external-precondition prohibition reaches the gate agent, and only there', async () => {
  const integration = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      impact: {
        ...IMPACT_INTERNAL,
        severity: 'Critical',
        rootCause: 'integration',
        externalPrecondition: 'the rate service returns a negative rate',
      },
    }),
  })
  const gates = promptFor(integration, 'gates')
  assert.match(gates, /Do NOT fail gateReachability, gateRealImpact or gatePocValidation/)
  assert.match(gates, /the rate service returns a negative rate/, 'the precondition is quoted, not summarised')
  assert.match(gates, /priced once already/, 'the reason has to reach the agent, not just the instruction')

  // The prohibition and the positive rule that follows it have to agree. The
  // first draft forbade failing on "no in-repo caller supplies the value" and
  // then, six lines later, listed "or has no caller at all" as a permitted FAIL
  // ground — the same fact, restated as an affirmative licence, which is the one
  // an agent acts on. That is verbatim the sweep251 run1 trace this whole change
  // exists to close: "There is no caller of charge() anywhere in this repository".
  // charge() genuinely has zero in-repo callers in the fixture (evals/
  // integration-cap/scaffold.sh documents the order pipeline as its caller and
  // does not create it), so the licence was reachable, not theoretical.
  assert.ok(
    !/has no caller at all/.test(gates),
    'the positive rule re-licenses the exact FAIL ground the paragraph above it forbids',
  )
  assert.match(
    gates,
    /absence of an in-repo caller is that same external premise restated/,
    'the no-caller ground has to be closed explicitly, not merely left unmentioned',
  )

  // And the cap is still what it was: the prohibition changes which gates may
  // fail, never the severity ceiling.
  assert.equal(integration.result.severity, 'Medium')

  // The bound. IMPACT_INTERNAL is `rootCause: internal`, and nothing about those
  // findings changes.
  const internal = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.ok(
    !/Do NOT fail gateReachability/.test(promptFor(internal, 'gates')),
    'the prohibition leaked onto an internal-root-cause finding, which weakens the gate everywhere',
  )

  // The other half of the same bound, and the one the first cut of 2.6.0 missed.
  // The prohibition paragraph was conditional; the GATE 2 CRITERION was not. It
  // dropped "attacker-controlled data reaches the sink" for every finding and
  // asserted that value provenance "has already been answered above, under Root
  // cause" — which is false for `internal`: 2.4b asks where the TRIGGER comes
  // from, not whether the value at the sink is attacker-controlled. Nothing in
  // code replaced it (`decideVerdict` reads the enum only), so an internal
  // finding whose sink takes a developer-set constant had no gate left to fail.
  assert.match(
    promptFor(internal, 'gates'),
    /attacker-controlled data reaches the sink/,
    'gate 2 stopped requiring attacker control on an internal root cause, and no code gate carries it',
  )
  assert.ok(
    !/answered above, under Root cause/.test(promptFor(internal, 'gates')),
    'an internal root cause is told provenance was already settled by 2.4b, which 2.4b does not settle',
  )
  // ...and the relaxed half really is the one an integration finding gets.
  assert.ok(
    !/attacker-controlled data reaches the sink/.test(gates),
    'the relaxation never reached the criterion, so gate 2 still charges the external premise twice',
  )
})

test('[concept-prover] the upstream-fix retraction decides, and needs a reference', async () => {
  const fixed = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      history: { fixed: 'YES', complete: true, reference: 'commit 99a4704 (#412)', searched: 'git log -p auth.py', evidence: 'the caller now digests the token' },
    }),
  })
  assert.equal(fixed.result.status, 'ALREADY_FIXED')
  assert.match(fixed.result.reason, /99a4704/)
  assert.ok(!labels(fixed).includes('impact'), 'the impact agent ran, so the retraction did not decide')

  const unreferenced = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      history: { fixed: 'YES', complete: true, reference: '  ', searched: 'git log', evidence: 'I think it was fixed' },
    }),
  })
  assert.notEqual(unreferenced.result.status, 'ALREADY_FIXED', 'an unreferenced retraction discards a real finding')
})

test('[concept-prover] the five false-positive challenges decide the confidence band', async () => {
  // Challenge 4 is scripted as REBUTTED on purpose: its win overrides the band
  // outright, so leaving it lost would test that rule instead of this one.
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({ challenge: CHALLENGE_LOST, 'challenge:already-fixed': CHALLENGE_WON }),
  })
  assert.equal(r.result.status, 'DO_NOT_SUBMIT')
  assert.equal(r.result.defeated, 1)
  assert.equal(r.result.band.label, 'LOW')
  assert.ok(!labels(r).includes('report'), 'a report was written for a finding four reviewers rejected')
  const dispatched = labels(r).filter((l) => l.startsWith('challenge:'))
  assert.deepEqual(
    dispatched.sort(),
    ['challenge:already-fixed', 'challenge:by-design', 'challenge:reachable', 'challenge:real-deployment', 'challenge:recoverable'],
    'all five challenges must be dispatched as independent agents',
  )
})

test('[concept-prover] the already-fixed challenge overrides the band', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({
      challenge: CHALLENGE_WON,
      'challenge:already-fixed': { ...CHALLENGE_LOST, reference: '99a4704 (#412)', complete: true, evidence: 'the digest call moved into the caller' },
    }),
  })
  assert.equal(r.result.status, 'ALREADY_FIXED', 'four defeated challenges must not carry an already-patched bug through')
  assert.equal(r.result.defeated, 4)
  assert.match(r.result.reason, /99a4704/)
})

test('[concept-prover] the artifact re-check is made by an agent that did not build the PoC', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({ 'artifact-check': { fileExists: true, lintExitZero: false, lintOutput: 'placeholder on line 4', evidence: 'ran it myself' } }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /poc-lint\.sh did not exit 0/)
  // The check is worth something only if it re-runs the linter itself.
  assert.match(promptFor(r, 'artifact-check'), /poc-lint\.sh --symbol/)
  assert.match(promptFor(r, 'artifact-check'), /billing\.charge\.charge/)
})

test('[concept-prover] the severity cap on the written report blocks rather than corrects', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs({ verification: { ...VERIFICATION, impact: { ...VERIFICATION.impact, rootCause: 'integration' } } }),
    agents: pocAgents({ report: { ...REPORT, severity: 'Critical' } }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /exceeds the Medium cap for a integration root cause/)
  assert.match(r.result.reason, /finding-negative-rate\.md/, 'the block must name the file that has to be corrected')
})

// ===================================================================
// old fp-check (git show main:plugins/fp-check/)
// ===================================================================

test('[old fp-check] the six-gate review decides the verdict', async () => {
  const pass = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.equal(pass.result.status, 'TRUE_POSITIVE')
  assert.equal(pass.result.reason, GATES_ALL_PASS.verdictReason, 'the verdict must come from decideVerdict, not from an earlier stage')
  assert.ok(labels(pass).includes('gates'), 'the six gates were never dispatched')

  // Paired rather than a flat loop over six. What is under test here is
  // unchanged — that decideVerdict, rather than something upstream, decides — but
  // a FAIL does not mean the same thing on every gate: Process and PoC Validation
  // grade whether the analysis showed its work, so a FAIL there is a missing fact
  // and not a refutation. The loop used to assert FALSE_POSITIVE for all six,
  // which is what let a thin write-up retire a finding whose four bug-grading
  // gates had all passed.
  for (const [gate, expected] of [
    ['gateProcess', 'NEEDS_MORE_INFO'],
    ['gateReachability', 'FALSE_POSITIVE'],
    ['gateRealImpact', 'FALSE_POSITIVE'],
    ['gatePocValidation', 'NEEDS_MORE_INFO'],
    ['gateMathBounds', 'FALSE_POSITIVE'],
    ['gateEnvironment', 'FALSE_POSITIVE'],
  ]) {
    const r = await runScript('triage-static.js', {
      args: standardArgs(),
      agents: staticAgents({ gates: { ...GATES_ALL_PASS, [gate]: 'FAIL' } }),
    })
    assert.equal(r.result.status, expected, `${gate} failing did not decide the verdict`)
    // Not `failed:` — the NEEDS_MORE_INFO reason reads "gate Process failed and
    // no gate refuted…", and the gate still has to be named either way.
    assert.match(r.result.reason, /^gate .* failed/)
  }
})

test('[old fp-check] standard/deep routing is decided from the dispatch', async () => {
  const std = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.equal(std.result.route, 'standard')
  for (const extra of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(!labels(std).includes(extra), `the standard route dispatched ${extra}; the cheap path is what makes it cheap`)
  }

  const deep = await runScript('triage-static.js', {
    args: standardArgs({ route: 'deep' }),
    agents: staticAgents({ 'api-contract': PROOF_SURVIVES, 'math-bounds': PROOF_SURVIVES, 'race-feasibility': PROOF_SURVIVES }),
  })
  assert.equal(deep.result.route, 'deep')
  for (const extra of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(labels(deep).includes(extra), `the deep route did not dispatch ${extra}; those three ARE what deep adds`)
  }
})

test('[old fp-check] bug-class routing escalates the four classes that need a proof', async () => {
  const classes = {
    'memory corruption': 'deep',
    'heap buffer overflow': 'deep',
    'integer truncation': 'deep',
    'TOCTOU race': 'deep',
    'algorithmic complexity DoS': 'deep',
    'input validation': 'standard',
    'injection': 'standard',
  }
  for (const [bugClass, expected] of Object.entries(classes)) {
    const r = await runScript('triage-static.js', {
      args: standardArgs({ finding: { ...finding, bugClass } }),
      agents: staticAgents({ 'api-contract': PROOF_SURVIVES, 'math-bounds': PROOF_SURVIVES, 'race-feasibility': PROOF_SURVIVES }),
    })
    assert.equal(r.result.route, expected, `bug class '${bugClass}' routed to ${r.result.route}`)
  }

  // 3+ trust boundaries in the path is the other escalation, and it fires on a
  // non-escalating bug class.
  const three = await runScript('triage-static.js', {
    args: standardArgs({ layers: [1, 2, 3].map((i) => ({ name: `l${i}`, location: `f.py:${i}` })) }),
    agents: staticAgents({ 'api-contract': PROOF_SURVIVES, 'math-bounds': PROOF_SURVIVES, 'race-feasibility': PROOF_SURVIVES }),
  })
  assert.equal(three.result.route, 'deep')
})

test('[old fp-check] the 13 devil\'s-advocate questions are asked on deep, the 7 spot-checks on standard', async () => {
  const std = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.match(promptFor(std, 'gates'), /7 spot-check questions/)

  const deep = await runScript('triage-static.js', {
    args: standardArgs({ route: 'deep' }),
    agents: staticAgents({ 'api-contract': PROOF_SURVIVES, 'math-bounds': PROOF_SURVIVES, 'race-feasibility': PROOF_SURVIVES }),
  })
  assert.match(promptFor(deep, 'gates'), /All 13 devil's-advocate questions/)

  // Both lists have to exist where the prompt sends the agent, or the routing
  // decides between two names for the same thing.
  const fpp = readFileSync(new URL('../skills/fp-check/references/false-positive-patterns.md', import.meta.url), 'utf8')
  const questions = fpp.match(/^\d+\. /gm) || []
  assert.ok(questions.length >= 13, `false-positive-patterns.md lists ${questions.length} numbered questions, expected 13`)
  assert.equal((fpp.match(/^\d+\. ★/gm) || []).length, 7, 'the 7 starred spot-check questions are not marked in the reference')
})

test('[old fp-check] the algebraic bounds proof is written by an agent on the deep route, and cannot vanish', async () => {
  const deepArgs = standardArgs({ finding: { ...finding, bugClass: 'integer overflow' } })
  const deepAgents = (over) =>
    staticAgents({
      'api-contract': PROOF_SURVIVES,
      'race-feasibility': { applies: false, verdict: 'UNCERTAIN', evidence: 'concurrency is not part of this trigger' },
      ...over,
    })

  // The proof itself: a dedicated agent, told to write the algebra rather than
  // asked whether it feels bounded. This is old fp-check's Phase 2.2.
  const passes = await runScript('triage-static.js', {
    args: deepArgs,
    agents: deepAgents({ 'math-bounds': { applies: true, verdict: 'FINDING_SURVIVES', evidence: 'no relation bounds the subtraction' } }),
  })
  assert.match(promptFor(passes, 'math-bounds'), /IF validation_check_passes THEN bounds_guarantee_holds/)
  assert.match(promptFor(passes, 'gates'), /math-bounds: FINDING_SURVIVES/, 'the algebra never reached the agent that decides gateMathBounds')

  // A refuting proof must either decide the finding itself or reach the verdict agent.
  // Which of the two is a live design question in this plugin — it was terminal
  // and is being changed to carried — but "neither" is a proof that was paid for
  // and thrown away, and that is what this asserts against.
  const blocks = await runScript('triage-static.js', {
    args: deepArgs,
    agents: deepAgents({ 'math-bounds': { applies: true, verdict: 'FINDING_REFUTED', evidence: 'size >= MIN and MIN >= sizeof(hdr), so size - sizeof(hdr) cannot underflow' } }),
  })
  const decided = blocks.result.status === 'NOT_EXPLOITABLE' && /math-bounds/.test(blocks.result.reason)
  const carried = labels(blocks).includes('gates') && /math-bounds/.test(promptFor(blocks, 'gates'))
  assert.ok(decided || carried, `a blocking algebraic proof neither decided the finding nor reached the verdict agent (status ${blocks.result.status})`)

  // And Gate 5 itself is arithmetic over the verdict agent's answer, on both
  // routes: a FAIL is a FALSE POSITIVE that names the gate.
  const failed = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ gates: { ...GATES_ALL_PASS, gateMathBounds: 'FAIL' } }),
  })
  assert.equal(failed.result.status, 'FALSE_POSITIVE')
  assert.match(failed.result.reason, /Math Bounds/)
})

test('[old fp-check] on the STANDARD route the bounds proof is only a self-report', async () => {
  // Pinned, not celebrated. The standard route is the default, it dispatches no
  // agent that writes algebra, and `gateMathBounds: 'N/A'` is an accepted pass —
  // so on the cheap path old fp-check's Gate 5 is a question the verdict agent
  // answers about itself. Anything that changes this should change this test.
  const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.ok(!labels(r).includes('math-bounds'), 'the standard route now dispatches the algebra agent — update this test and the report')
  assert.equal(r.result.status, 'TRUE_POSITIVE', "gateMathBounds: 'N/A' no longer passes on the standard route")
  assert.match(promptFor(r, 'gates'), /gateMathBounds/, 'the verdict agent is not even asked about Gate 5 on the standard route')
})

test('[old fp-check] batch triage accounts for a finding whose sub-workflow died', async () => {
  // This test used to pin the ABSENCE of batch triage, because every workflow
  // destructured a single `finding` and the batch was the orchestrator's loop
  // with no gate behind it. triage-batch.js is that gate, so the guard now
  // exercises the capability instead of recording its loss.
  //
  // The assertion is the one thing prose could never make good on: a finding
  // whose Stage 1 returned nothing is REPORTED, matched by id. Tallying the
  // returned array instead would show two of two verified with the third gone.
  const r = await runScript('triage-batch.js', {
    args: batchArgs(['a', 'b', 'c']),
    agents: { context: CONTEXT, chain: NO_CHAIN },
    workflows: (name, sub) => {
      assert.equal(name, 'fp-check:triage-static', 'the batch dispatches something other than Stage 1')
      return sub.finding.summary === 'finding b' ? null : blockedAt('authz')
    },
  })
  assert.equal(r.result.status, 'BATCH_TRIAGED')
  assert.deepEqual(r.result.findings.map((f) => f.id), ['a', 'c'])
  assert.deepEqual(r.result.unverified.map((u) => u.id), ['b'])
  assert.match(r.result.unverified[0].why, /returned nothing/)
  assert.ok(
    r.logs.some((l) => /UNVERIFIED b/.test(l)),
    'a finding that was never triaged is absent from the log as well as from the ledger',
  )
})

test('[old fp-check] the exploit-chain check compares two findings, in code', async () => {
  // "Two NOT_EXPLOITABLE results whose blocking layers differ" is the comparison
  // no single-finding workflow can make. It is `pairReason` now, and this asserts
  // the whole route: the pair is selected, an agent is dispatched for it, and the
  // chain reaches the return.
  assert.ok(/exploit chain/i.test(SKILL_SRC), 'SKILL.md no longer mentions exploit chains')
  const r = await runScript('triage-batch.js', {
    args: batchArgs(),
    agents: { context: CONTEXT, chain: CHAIN_CONFIRMED },
    workflows: (name, sub) => blockedAt(sub.finding.summary === 'finding a' ? 'authz' : 'quota'),
  })
  assert.equal(r.result.chains.length, 1, 'no chain was reported between two differently-blocked findings')
  assert.ok(
    labels(r).some((l) => l.startsWith('chain:')),
    'no chain agent was dispatched, so the comparison was never made',
  )
})

test('[old fp-check] the batch context reaches the prompts that would re-derive it', async () => {
  // The other half of the batch's cost argument, and the half that lives in
  // triage-static: deriving the router, the trust boundaries and the framework's
  // recovery default ONCE is only a saving if the children are actually told.
  // triage-static ignores args it does not read, so a context that never reached
  // a prompt would be silently dropped and the Context phase would be decoration.
  const r = await runScript('triage-static.js', {
    args: standardArgs({ context: 'Framework: flask 3.0; werkzeug returns 500 and the worker survives' }),
    agents: staticAgents(),
  })
  for (const label of ['layer:sign-check', 'recovery']) {
    assert.match(promptFor(r, label), /werkzeug returns 500/, `the ${label} agent was not given the shared context`)
  }
  // And a single dispatch, which supplies none, must not get the heading with
  // nothing under it — an empty block reads to the agent as an established fact.
  const alone = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.ok(!/Shared context/.test(promptFor(alone, 'recovery')), 'a single dispatch was given an empty context heading')
})

test('[old fp-check] two findings behind the SAME wall are not paired', async () => {
  // The other half of the rule, and the half that keeps this phase affordable:
  // the same blocking layer means the same wall, and composing two findings that
  // die at it changes nothing.
  const r = await runScript('triage-batch.js', {
    args: batchArgs(),
    agents: { context: CONTEXT, chain: CHAIN_CONFIRMED },
    workflows: () => blockedAt('authz'),
  })
  assert.deepEqual(r.result.chainCandidates, [], 'identically-blocked findings were paired')
  assert.ok(!labels(r).some((l) => l.startsWith('chain:')), 'an agent was paid for a pair with nothing to compose')
})

// ===================================================================
// online-triage
// ===================================================================

test('[online-triage] the policy read decides: offline halts before any scope claim', async () => {
  const r = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ policy: { ...POLICY, reachedNetwork: false } }),
  })
  assert.equal(r.result.status, 'OFFLINE')
  assert.ok(!labels(r).includes('inscope'), 'a scope verdict was formed with no document read')
  assert.ok(!labels(r).some((l) => l.startsWith('past-bugs:')), 'the past-bug fan-out was paid for offline')
})

test('[online-triage] the scope verdict halts only with a quoted clause', async () => {
  const clause = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ inscope: { verdict: 'out-of-scope', clause: 'SECURITY.md: "internal services are not in scope"', severity: 'Unknown', evidence: 'clause 3' } }),
  })
  assert.equal(clause.result.status, 'OUT_OF_SCOPE')
  assert.match(clause.result.reason, /internal services are not in scope/)

  const unclaused = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ inscope: { verdict: 'out-of-scope', clause: '   ', severity: 'Unknown', evidence: 'it feels out of scope' } }),
  })
  assert.equal(unclaused.result.status, 'NEEDS_MORE_INFO')
})

test('[online-triage] one past-bug agent per named venue, and a duplicate is terminal', async () => {
  const sources = ['github-issues', 'github-advisories', 'mailing-list'].map((label) => ({ label, query: `${label} query` }))
  const r = await runScript('triage-online.js', {
    args: onlineArgs({ sources }),
    agents: onlineAgents({
      'past-bugs': PAST_NOTHING,
      'past-bugs:github-advisories': { ...PAST_NOTHING, result: 'similar-bugs-found', duplicate: true, links: 'GHSA-xxxx-yyyy-zzzz' },
    }),
  })
  assert.deepEqual(
    labels(r).filter((l) => l.startsWith('past-bugs:')).sort(),
    ['past-bugs:github-advisories', 'past-bugs:github-issues', 'past-bugs:mailing-list'],
  )
  assert.equal(r.result.status, 'DUPLICATE')
  assert.match(r.result.reason, /GHSA-xxxx-yyyy-zzzz/)
})

test('[online-triage] venues beyond the cap are declared unchecked rather than dropped', async () => {
  const sources = [1, 2, 3, 4, 5, 6, 7].map((i) => ({ label: `venue-${i}`, query: `q${i}` }))
  const r = await runScript('triage-online.js', {
    args: onlineArgs({ sources }),
    agents: onlineAgents({ 'past-bugs': PAST_NOTHING }),
  })
  assert.equal(labels(r).filter((l) => l.startsWith('past-bugs:')).length, 6)
  assert.deepEqual(r.result.beyondCap, ['venue-7'])
  assert.match(promptFor(r, 'summary'), /venue-7/)
})

test('[online-triage] the downstream-users census decides, and only where it should', async () => {
  // The parent's `triage-online-users` role — find the popular public consumers
  // and check whether any exhibits the buggy pattern — is what turns "a misusable
  // API" into a severity, and it is the only role in any parent that produced
  // evidence about the world rather than about the project. It did not survive the
  // merge; this test used to pin that absence.
  //
  // Restored in 2.3.0, gated in code on what Stage 2 already knows rather than on
  // a third question at Step 0. Which makes the ordering below the thing to hold:
  // the census must fire on the findings whose severity depends on a consumer, and
  // must not be paid for on the ones directly exploitable in the target.
  assert.ok(
    /downstream users/i.test(ONLINE_SRC),
    'triage-online.js no longer advertises the downstream-users census',
  )

  // rootCause `integration`: the attack needs a failure on the client's side of
  // the boundary, so who those clients are and what they do is the severity.
  const clientSide = {
    ...VERIFICATION,
    impact: { result: 'VERIFIED', impact: 'a caller-built filter reaches the query', rootCause: 'integration', classification: 'vulnerability' },
  }
  const ran = await runScript('triage-online.js', {
    args: onlineArgs({ verification: clientSide }),
    agents: onlineAgents({ 'past-bugs': PAST_NOTHING }),
  })
  assert.ok(labels(ran).includes('downstream-users'), 'the census agent is not dispatched on an integration root cause')
  assert.equal(ran.result.census.state, 'performed')
  assert.match(promptFor(ran, 'summary'), /Downstream-consumer census/)

  // And the negative half, which is the reason this is a gate and not one more
  // agent in the History phase: VERIFICATION is internal, a vulnerability, driven
  // by an in-repo caller, so the census answers a question nobody asked.
  const skipped = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ 'past-bugs': PAST_NOTHING }),
  })
  assert.ok(!labels(skipped).includes('downstream-users'), 'the census is paid for on a directly exploitable bug')
  // Carried, not merely logged: `beyondCap` is the precedent for a skipped step
  // that reached the summary as an absence and read as a clean result.
  assert.equal(skipped.result.census.state, 'not-applicable')
  assert.ok(skipped.result.census.why.trim(), 'the skip is carried with no reason')
})

// ===================================================================
// the merge itself: ordering, not presence
// ===================================================================

test('[merge] the brocard pre-gate is gone, and no agent decides on the shape of the claim', async () => {
  // This used to pin the ordering: the four brocards were the first four agents
  // dispatched, and being cheap and first they won the race on findings the
  // specialised gates were built for. Measured across 63 with-plugin runs, a
  // brocard DISMISS decided 12 of them while `upstreamFixStands`, `capSeverity`,
  // `missingPrecondition` and `decideVerdict` fired zero times between them.
  //
  // Removed in 2.5.0 rather than reordered again. The four tests are guidance in
  // references/dismissal-grounds.md, applied by the agents that hold the traced
  // path — which is where they were always answerable. What this pins is that the
  // removal is real on both sides: no agent, and the guidance actually exists and
  // is reachable from the agent that decides classification.
  const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.ok(
    !labels(r).some((l) => l.startsWith('brocard:')),
    'a brocard agent is dispatched again; if that is deliberate, this test and dismissal-grounds.md are both stale',
  )
  assert.ok(!/BROCARD_SCHEMA|triageBrocards/.test(STATIC_SRC), 'the brocard gate machinery is back in the script')

  // The guidance side. A removal that deletes the mechanism and loses the content
  // is not what was decided, and a dangling reference in a prompt is invisible
  // until an agent reports the file is missing — which has happened here before.
  const grounds = readFileSync(
    new URL('../skills/fp-check/references/dismissal-grounds.md', import.meta.url),
    'utf8',
  )
  for (const ground of [/already hold/i, /specification/i, /documentation describes/i, /cure is worse/i]) {
    assert.match(grounds, ground, 'a dismissal ground was lost with the pre-gate rather than moved to the guidance')
  }
  assert.match(
    promptFor(r, 'impact'),
    /dismissal-grounds\.md/,
    'the agent that decides classification is not pointed at the grounds, so the guidance reaches nobody',
  )
})

// The half of the old carried-question test that still holds: Stage 3 refuses a
// finding Stage 1 did not confirm. That is not about brocards — NEEDS_MORE_INFO
// arrives from the six gates and from an UNCERTAIN layer too — and it is the gate
// that stops a PoC being built for an unconfirmed finding.
test('[merge] Stage 3 refuses a finding Stage 1 returned as NEEDS MORE INFO', async () => {
  const poc = await runScript('triage-poc.js', {
    args: pocArgs({ verification: { ...VERIFICATION, status: 'NEEDS_MORE_INFO' } }),
    agents: pocAgents(),
  })
  assert.equal(poc.result.status, 'BLOCKED')
  assert.equal(labels(poc).length, 0, 'a builder was spent on a finding Stage 1 did not confirm')
})

test('[merge] every Stage 1 exit after the impact agent reports the capped severity', async () => {
  // capSeverity is applied before the early exits on purpose. If a later exit
  // returned the agent's own number the cap would be unreachable exactly on the
  // findings it exists to bound.
  const exits = [
    { name: 'missing precondition', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'external', externalPrecondition: '' } } },
    { name: 'failed gate', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service misbehaves' }, gates: { ...GATES_ALL_PASS, gateReachability: 'FAIL' } } },
    { name: 'true positive', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service misbehaves' } } },
  ]
  for (const { name, over } of exits) {
    const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents(over) })
    assert.equal(r.result.severity, 'Medium', `the ${name} exit returned an uncapped severity`)
    assert.ok(r.result.severityCorrection, `the ${name} exit reported no correction`)
  }
})

// --------------------------------------------------------- shared fixtures
//
// Declared below the tests that use them: function declarations hoist, and
// keeping the const fixtures for one workflow next to the others made the
// static-stage fixtures at the top of the file harder to read than the tests.

const VERIFICATION = {
  status: 'TRUE_POSITIVE',
  impact: {
    // `result` is required by Stage 2's dispatch contract: `impactLine` branches
    // on it, and an omitted one tells all five agents Stage 1 established nothing.
    result: 'VERIFIED',
    impact: 'a negative rate credits the account',
    rootCause: 'internal',
    classification: 'vulnerability',
  },
  severity: 'High',
  severityCorrection: '',
  history: { fixed: 'NO', searched: 'git log -p billing/, CHANGELOG' },
}

const POC_BUILT = {
  built: true,
  pocType: 'test-integrated',
  path: 'tests/test_negative_rate.py',
  absolutePath: '/w/tests/test_negative_rate.py',
  command: 'pytest tests/test_negative_rate.py',
  executed: true,
  output: 'balance 0 -> 12500; VULNERABLE',
  invokedSymbol: 'billing.charge.charge',
  lintPassed: true,
}

const ARTIFACT_OK = { fileExists: true, lintExitZero: true, reimplementation: 'NOT_DEFINED', reRun: 'REPRODUCED', reRunNotes: '', evidence: 'ran it and it reproduces' }
const CHALLENGE_WON = { challenge: 'the path is unreachable', rebuttal: 'the entry point drives it', winner: 'REBUTTAL', evidence: 'see the PoC setup' }
const CHALLENGE_LOST = { challenge: 'the path is unreachable', rebuttal: 'none found', winner: 'CHALLENGE', evidence: 'the fixture constructs state no caller reaches' }
const REPORT = { severity: 'Medium', severityRationale: 'ledger corruption behind an internal trust boundary', reportPath: '/w/finding-negative-rate.md', unproven: 'that the rate service can be made to misbehave' }

function pocArgs(over = {}) {
  return {
    baseDir: BASE,
    finding,
    verification: VERIFICATION,
    envelope: { level: 1, hosts: [], destructive: false },
    candidates: [{ name: 'negative-rate', description: 'drive charge() through POST /orders', entryPoint: 'api/orders.py:12', payload: 'qty=125, rate=-1.00' }],
    ...over,
  }
}

function pocAgents(over = {}) {
  return { build: POC_BUILT, 'artifact-check': ARTIFACT_OK, challenge: CHALLENGE_WON, report: REPORT, ...over }
}

const POLICY = {
  reachedNetwork: true,
  sourcesRead: 'https://example.test/SECURITY.md',
  policyUrl: 'https://example.test/SECURITY.md',
  inScopeClasses: 'authentication, billing integrity',
  outOfScopeClasses: 'self-XSS',
  evidence: 'read the policy',
}
const REACHABILITY = { driver: 'in-repo-caller', eligibilityCaveats: 'requires a compromised rate service', evidence: 'charge() is called from the public order pipeline' }
const INSCOPE = { verdict: 'in-scope', clause: 'SECURITY.md: "billing integrity is in scope"', severity: 'Medium', evidence: 'billing integrity is named' }
const PAST_NOTHING = { result: 'nothing', coverage: 'searched 4 pages of results', duplicate: false, evidence: 'nothing similar' }
const CENSUS = {
  reachedNetwork: true,
  result: 'no-confirmed-users',
  pattern: 'a client passing an unvalidated rate through to charge()',
  coverage: 'the 40 dependents on the package index, searched for charge( and fetch_rate(',
  confirmed: '',
  severityEffect: 'lower',
  evidence: 'every dependent read validates the rate first',
}
const SUMMARY = { finalSeverity: 'Medium', scopeVerdict: 'in-scope', reasoning: 'the policy names billing integrity', confidence: 'medium', openQuestions: 'the rate service is not described in the policy', evidence: 'see above' }

function onlineArgs(over = {}) {
  return {
    baseDir: BASE,
    finding,
    verification: VERIFICATION,
    project: { name: 'example', url: 'https://example.test/example' },
    sources: [{ label: 'github-issues', query: 'repo:example/example negative rate' }],
    ...over,
  }
}

function onlineAgents(over = {}) {
  return {
    policy: POLICY,
    reachability: REACHABILITY,
    inscope: INSCOPE,
    'past-bugs': PAST_NOTHING,
    'downstream-users': CENSUS,
    summary: SUMMARY,
    ...over,
  }
}
