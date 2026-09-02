/**
 * Layer 2b: the call sites, not the helpers.
 *
 * `gate.test.mjs`, `build.test.mjs` and `review.test.mjs` test each pure helper
 * in isolation. That leaves the wiring untested, and a review demonstrated how
 * much that hides: disabling twelve separate call sites — the
 * `gate.status !== 'PROCEED'` halt, the `impact.result !== 'VERIFIED'` halt,
 * `isAcceptableBuild`, `alreadyFixedStands`, the band check, the severity cap —
 * left every existing test green. The helpers were covered; none was covered
 * where it is used, so twenty assertions about `decideGate` could not tell you
 * whether `decideGate`'s answer was acted on.
 *
 * These run the real script bodies against scripted agent responses and assert
 * on the status that comes back.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { runScript } from './extract.mjs'

const BASE = '/plugin/skills/fp-check'

// ------------------------------------------------------------ triage-static

const VERIFY_ARGS = {
  baseDir: BASE,
  finding: {
    summary: 'negative amount reverses a transfer',
    sink: 'ledger.py:12',
    component: 'ledger',
    claimedImpact: 'attacker drains an account',
    bugClass: 'logic error',
    threatModel: 'an authenticated caller of POST /transfer moves a negative amount',
  },
  entryPoint: { description: 'POST /transfer', location: 'api.py:8', payload: '-500' },
  layers: [{ name: 'amount-check', location: 'ledger.py:9', checks: 'sender has funds' }],
  scope: 'the ledger module',
}

const PASSING_LAYER = { verdict: 'PAYLOAD_REACHES_SINK', evidence: 'quoted code' }
const UNFIXED = {
  fixed: 'NO',
  reference: '',
  searched: 'git log -p -- ledger.py, issues, CHANGELOG',
  evidence: 'nothing found',
}
const ALL_GATES_PASS = {
  gateProcess: 'PASS',
  gateReachability: 'PASS',
  gateRealImpact: 'PASS',
  gatePocValidation: 'PASS',
  gateMathBounds: 'N/A',
  gateEnvironment: 'PASS',
  unresolvedUncertainty: '',
  verdictReason: 'a negative amount reaches ledger.debit unvalidated and credits the sender',
  evidence: 'ledger.py:12 with the trace above',
}
const RECOVERY = { recoveryExists: false, effectiveImpact: 'balance corrupted', evidence: 'no recover' }
const IN_SCOPE = { inScope: 'YES', byDesign: false, byDesignIndicators: 0, evidence: 'in scope' }
const VERIFIED = {
  result: 'VERIFIED',
  impact: 'drains an account',
  rootCause: 'internal',
  classification: 'vulnerability',
  severity: 'High',
  severityRationale: 'unauthenticated, no recovery, full balance control',
  evidence: 'ran it',
}

// Keyed by the label PREFIX where labels are per-item: runScript falls back to
// `agents[label.split(':')[0]]`, so one entry answers a whole fan-out and one
// `layer` entry answers every layer agent.
const verifyAgents = (over = {}) => ({
  layer: PASSING_LAYER,
  recovery: RECOVERY,
  'threat-model': IN_SCOPE,
  history: UNFIXED,
  impact: VERIFIED,
  gates: ALL_GATES_PASS,
  ...over,
})

test('the happy path reaches TRUE_POSITIVE through the impact and gate agents', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents(),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.ok(calls.some((c) => c.label === 'impact'), 'checkpoint 2.4 must actually run')
  assert.ok(calls.some((c) => c.label === 'gates'), 'the six-gate review must actually run')
  assert.equal(result.severity, 'High', 'an internal root cause is not capped')
})

// `layers: []` with a `layersSearched` declaration is a SUPPORTED dispatch, and
// on it the gate prompt says outright that the layer stage rests on a caller
// assertion rather than on agent verification — so a Process FAIL is a sentence
// an honest agent writes on it. That used to come back FALSE POSITIVE, retiring a
// finding whose four bug-grading gates had all passed.
const NO_LAYERS = {
  ...VERIFY_ARGS,
  layers: [],
  layersSearched: 'read api.py and ledger.py end to end; nothing checks the sign of amount on the path',
}

test('a Process FAIL on the caller-declared no-layers dispatch is NEEDS MORE INFO', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: NO_LAYERS,
    agents: verifyAgents({
      gates: {
        ...ALL_GATES_PASS,
        gateProcess: 'FAIL',
        verdictReason: 'no agent verified the absence of a validation layer; the caller asserted it',
      },
    }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /gate Process failed/)
  assert.match(result.reason, /no agent verified the absence/)
  // Proves the reachability claim rather than assuming it: this is the prompt
  // text that invites the FAIL in the first place.
  const gatePrompt = calls.find((c) => c.label === 'gates').prompt
  assert.match(gatePrompt, /the caller declared this rather than any agent verifying it/)
})

test('the same dispatch still reaches TRUE_POSITIVE when the process gate passes', async () => {
  const { result } = await runScript('triage-static.js', { args: NO_LAYERS, agents: verifyAgents() })
  assert.equal(result.status, 'TRUE_POSITIVE', 'the supported no-layers dispatch became a permanent NEEDS MORE INFO')
})

// The repro, pinned. `layersSearched: 'n/a'` cleared the arg gate and
// `decideGate`'s zero-layer guard, and Stage 1 returned TRUE_POSITIVE at High
// having dispatched no layer agent at all — with the affirmative counter-check
// `passed.length !== attemptedLayers` vacuous at 0 !== 0, so nothing in the stage
// established that the payload reaches the sink.
test('a stand-in for layersSearched does not buy a verdict on zero layer agents', async () => {
  for (const layersSearched of ['n/a', 'none', 'TBD', '.']) {
    const { result, calls } = await runScript('triage-static.js', {
      args: { ...VERIFY_ARGS, layers: [], layersSearched },
      agents: verifyAgents(),
    })
    assert.equal(result.status, 'BLOCKED', layersSearched)
    assert.match(result.reason, /layersSearched/)
    assert.ok(!calls.some((c) => c.label.startsWith('layer')), 'a layer agent ran on an empty list')
  }
})

// The other direction, so a future tightening of the rule cannot quietly re-close
// checkpoint 2.2's "or confirmed none exist" half.
test('an audited "nothing validates this path" still reaches a verdict', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: {
      ...VERIFY_ARGS,
      layers: [],
      layersSearched: 'read api.py and ledger.py end to end; no sign or bounds check between transfer and debit',
    },
    agents: verifyAgents(),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.ok(!calls.some((c) => c.label.startsWith('layer')), 'there were no layers to inspect')
  assert.ok(calls.some((c) => c.label === 'impact'), 'the declared-absence path must still reach the impact agent')
})

test('a Reachability FAIL is still a FALSE_POSITIVE end to end', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ gates: { ...ALL_GATES_PASS, gateReachability: 'FAIL' } }),
  })
  assert.equal(result.status, 'FALSE_POSITIVE')
  assert.match(result.reason, /Reachability/)
})

// The gate prompt used to tell the agent the number had been capped when it had
// not, and forbid three gate failures on that false premise. The cap matched
// `integration` or `external` affirmatively; the prompt and `missingPrecondition`
// branched on `!== 'internal'` — so `third-party`, which nothing rejects, got the
// relaxation and the path-only gate-2 wording with the cap never applied, under a
// sentence reading "the severity is already capped at Critical because of it."
const gatePrompt = (calls) => calls.find((c) => c.label === 'gates').prompt

test('an off-enum root cause is capped, and the prompt says what was actually done', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      impact: {
        ...VERIFIED,
        rootCause: 'third-party',
        externalPrecondition: 'the upstream rate feed returns a negative rate',
        severity: 'Critical',
      },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'Medium', 'a root cause the enum does not list still requires an external failure')
  assert.match(result.severityCorrection, /third-party/)
  const prompt = gatePrompt(calls)
  assert.ok(
    prompt.includes('the severity is already capped at Medium because of it.'),
    'the relaxation may only assert a cap that was actually paid',
  )
  assert.ok(
    prompt.includes('Do NOT fail gateReachability, gateRealImpact or gatePocValidation'),
    'the relaxation itself still applies: the trigger is external either way',
  )
})

// Looped over the CASINGS, and that is what pins the three gate-prompt
// conditionals rather than only the cap. `third-party` above cannot reach them:
// the cap change alone already produces the right prompt there, so reverting all
// three prompt reads to `=== 'internal'` left it — and the whole suite — green,
// while `Internal` was told "the severity is already capped at Critical because
// of it" over a cap that had not been applied, and forbidden on that premise from
// failing three gates. A casing variant is the only input on which the cap and
// the prompts can disagree, so it is the only one that grades them separately.
test('an internal root cause keeps the strict gate wording and its severity', async () => {
  for (const rootCause of ['internal', 'Internal', '  internal  ']) {
    const { result, calls } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, rootCause, severity: 'Critical' } }),
    })
    assert.equal(result.severity, 'Critical', rootCause)
    assert.equal(result.severityCorrection, '', rootCause)
    const prompt = gatePrompt(calls)
    assert.ok(prompt.includes('attacker-controlled data reaches the sink'), `${rootCause}: gate 2 keeps its trust-boundary half`)
    assert.ok(!prompt.includes('Do NOT fail gateReachability'), `${rootCause}: nothing was priced in a cap, so nothing may be relaxed`)
    assert.ok(
      !prompt.includes('the severity is already capped'),
      `${rootCause}: the prompt asserted a cap that was never applied`,
    )
    assert.ok(!prompt.includes('external precondition:'), `${rootCause}: an in-repo trigger has no external precondition to state`)
  }
})

// An information-disclosure finding: standard in the Route table of
// references/bug-class-verification.md. The only thing separating it from the
// control is that the submitter wrote the words "stack trace".
const TRACE_ARGS = {
  ...VERIFY_ARGS,
  finding: {
    summary: 'the 500 handler returns the raw exception to the caller',
    sink: 'api/handlers.py:40',
    component: 'api',
    claimedImpact: 'internal paths and SQL leak to an unauthenticated caller',
    bugClass: 'information disclosure via stack trace',
    threatModel: 'an unauthenticated caller of any endpoint that raises',
  },
  entryPoint: { description: 'GET /orders/{id}', location: 'api/handlers.py:12', payload: "id=';" },
  layers: [{ name: 'error-filter', location: 'api/handlers.py:35', checks: 'sanitises some messages' }],
}
// No entry for api-contract, math-bounds or race-feasibility: the absence IS the
// assertion. If the route escalates, those three are dispatched, answer nothing,
// and `deadProofs` returns BLOCKED.
const traceAgents = verifyAgents({ impact: { ...VERIFIED, severity: 'Low' } })

test('a bug class that merely CONTAINS an escalation keyword does not buy the deep route', async () => {
  const { result, calls } = await runScript('triage-static.js', { args: TRACE_ARGS, agents: traceAgents })
  assert.equal(result.route, 'standard')
  for (const proof of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(!calls.some((c) => c.label === proof), `${proof} must not be dispatched`)
  }
  // Before: 'stack trace' escalated, the three proof agents were dispatched and
  // never scripted, and `deadProofs` returned BLOCKED — NEEDS MORE INFO to the
  // user, on a finding every gate had passed.
  assert.equal(result.status, 'TRUE_POSITIVE')
})

test('a stopped payload halts before the impact agent is ever spent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: { verdict: 'PAYLOAD_STOPPED_HERE', evidence: 'rejects negatives' } }),
  })
  assert.equal(result.status, 'NOT_EXPLOITABLE')
  assert.ok(
    !calls.some((c) => c.label === 'impact'),
    'a blocked path must not pay for checkpoint 2.4',
  )
})

test('an UNCERTAIN verdict needs more info: the gate decision is acted on', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: { verdict: 'UNCERTAIN', evidence: 'could not trace' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
})

// `[]` cleared `need` (not undefined, not null, not a blank string) and then
// stringified to '' in the shape guard, which skips on a falsy `base` — so the
// validator reported nothing, every `${baseDir}/references/` read resolved under
// a bare `/references/`, and five agents answered from memory behind a
// TRUE_POSITIVE that looked complete.
test('a baseDir that stringifies to nothing is refused before any agent runs', async () => {
  for (const baseDir of [[], [null], ['']]) {
    const { result, calls } = await runScript('triage-static.js', {
      args: { ...VERIFY_ARGS, baseDir },
      agents: verifyAgents(),
    })
    assert.equal(result.status, 'BLOCKED', JSON.stringify(baseDir))
    assert.equal(calls.length, 0, 'agents were dispatched on a baseDir no reference read can resolve')
  }
})

test('a dead layer agent blocks rather than proceeding', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: null }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /returned nothing/)
})

test('a dead recovery agent blocks: checkpoint 2.3 is not skipped', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ recovery: null }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /recovery/)
})

test('an out-of-scope threat verdict halts', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ 'threat-model': { inScope: 'NO', byDesign: false, evidence: 'infra' } }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE')
})

// The results of the one parallel() call used to be disaggregated by SHAPE —
// `.filter(Boolean)` and then `results.find((r) => r.inScope)` — over an array
// whose positions had already been destroyed. The recovery thunk precedes the
// threat thunk, so a recovery agent volunteering an incidental `inScope` key won
// the lookup, the real OUT_OF_SCOPE verdict was silently discarded, and this
// exact input returned PROCEED. Only `additionalProperties: false` stood between
// that and a shipped false positive, and deleting it from all four schemas left
// the whole free suite green, so nothing pinned the guard.
//
// The fix slices positionally out of the UNFILTERED parallel() array. This
// grades that: the threat agent's verdict must win regardless of what any other
// agent volunteers.
test('a recovery agent volunteering inScope cannot displace the threat verdict', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      recovery: { ...RECOVERY, inScope: 'YES' },
      'threat-model': { inScope: 'NO', byDesign: false, byDesignIndicators: 0, evidence: 'infra' },
    }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE', 'the threat agent decides 3.1, not whoever answers first')
  assert.equal(result.threat.inScope, 'NO', 'the recovery result must not be reported as the threat verdict')
  assert.equal(result.recovery.recoveryExists, false, 'and recovery must still be the recovery result')
})

// The mirror image: a threat agent volunteering a `verdict` key used to be
// counted as a sixth layer verdict, which drove `missing` negative in decideGate.
test('a threat agent volunteering a verdict key is not counted as a layer', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ 'threat-model': { ...IN_SCOPE, verdict: 'PAYLOAD_REACHES_SINK' } }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.equal(result.layers.length, 1, 'exactly one layer agent was dispatched')
})

test('by-design halts as NOT_VULNERABLE', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      'threat-model': { inScope: 'YES', byDesign: true, byDesignIndicators: 2, evidence: 'documented escape hatch' },
    }),
  })
  assert.equal(result.status, 'NOT_VULNERABLE')
})

test('NOT_VERIFIED does not reach a positive verdict', async () => {
  // The gate reads `!== 'VERIFIED'`; a two-way check on a three-value enum let
  // NOT_VERIFIED fall through to a verdict, logged as "Verified impact".
  //
  // The two failing values do NOT collapse to one status, and that is deliberate.
  // DISPROVEN is positive evidence that there is no impact — a false positive.
  // NOT_VERIFIED is the absence of evidence either way, which is the conflation
  // that killed a real finding: the impact agent performed the downgrade it was
  // asked for, returned NOT_VERIFIED because the claim AS STATED did not hold,
  // and the run reported a demonstrable bug as not exploitable.
  for (const [bad, status] of [
    ['NOT_VERIFIED', 'NEEDS_MORE_INFO'],
    ['DISPROVEN', 'NOT_EXPLOITABLE'],
  ]) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, result: bad } }),
    })
    assert.equal(result.status, status, `${bad} must not reach a positive verdict`)
  }
})

// The enum has three values; `result` can hold any string. The runtime validator
// enforces `required` and treats `enum` as advisory, and this branch graded by
// exclusion — so NOT_EXPLOITABLE, which triage-poc refuses to build for and
// triage-online refuses to check, was the fall-through for every grade the script
// does not recognise. An impact agent answering `Verified` in the wrong case had
// its own evidence FOR the impact relayed to the user as "FALSE POSITIVE — no
// attacker-reachable path".
test('an off-enum impact grade is NEEDS_MORE_INFO, not a terminal dismissal', async () => {
  // 'DISPROVED' is the deliberate near-miss of the one grade that IS a dismissal;
  // '' is the present-but-empty case `required` lets through.
  for (const bad of ['Verified', 'verified', 'VERIFIED_WITH_LOWER_SEVERITY', 'PARTIAL', 'DISPROVED', '']) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, result: bad, evidence: 'traced end to end' } }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO', `${JSON.stringify(bad)} must not dismiss the finding`)
    assert.match(
      result.reason,
      /not one of VERIFIED, NOT_VERIFIED or DISPROVEN/,
      `${JSON.stringify(bad)}: the reason names the unusable grade`,
    )
    assert.doesNotMatch(
      result.reason,
      /traced end to end/,
      `${JSON.stringify(bad)}: the agent's evidence FOR the impact is not the fact still missing`,
    )
  }
})

// IMPACT_SCHEMA requires `evidence`, and JSON Schema `required` checks presence
// rather than content: `evidence: ''` validates. The 2.4 branch relayed it
// verbatim, so SKILL.md's failure protocol rendered as "Reason:" with nothing
// after it — a halt the orchestrator cannot explain to the user. decideGate's
// two agent-sourced reasons already had a `why()` fallback; this sibling did not.
test('an empty-evidence NOT_VERIFIED still explains itself', async () => {
  for (const evidence of ['', '   ']) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, result: 'NOT_VERIFIED', evidence } }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO')
    assert.ok(
      result.reason && result.reason.trim(),
      `evidence ${JSON.stringify(evidence)} produced a halt with no reason`,
    )
    assert.match(result.reason, /NOT_VERIFIED/)
  }
})

test('a real evidence string is relayed rather than replaced by the fallback', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      impact: { ...VERIFIED, result: 'DISPROVEN', evidence: 'the sink coerces to unsigned first' },
    }),
  })
  assert.equal(result.reason, 'the sink coerces to unsigned first')
})

test('an integration root cause with no precondition needs more info at 2.4b', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ impact: { ...VERIFIED, rootCause: 'integration' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /external precondition/)
})

test('an integration root cause WITH a precondition proceeds', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      impact: {
        ...VERIFIED,
        rootCause: 'integration',
        externalPrecondition: 'the upstream API returns a negative length',
      },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  // And the cap fires: an integration root cause cannot carry the High the
  // impact agent asked for. This is one of the two mechanisms the head-to-head
  // attributed its delta to, so it is asserted where it is USED, not only in
  // capSeverity's unit tests.
  assert.equal(result.severity, 'Medium')
  assert.match(result.severityCorrection, /integration/)
})

test('a bad arg shape returns BLOCKED without spending an agent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: { ...VERIFY_ARGS, layers: [] },
    agents: verifyAgents(),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0, 'the arg gate must reject before any fan-out')
})

test('no more layer agents are dispatched than the cap allows', async () => {
  const four = Array.from({ length: 4 }, (_, i) => ({ name: `l${i}`, location: `a.py:${i}` }))
  const { calls } = await runScript('triage-static.js', {
    args: { ...VERIFY_ARGS, layers: four },
    agents: verifyAgents(),
  })
  const layerCalls = calls.filter((c) => c.label.startsWith('layer:'))
  assert.equal(layerCalls.length, 4)
})

// `citedReference` was tested; the retraction it gates was not tested against a
// path, and that is precisely what let a `file:line` reference ship as a
// citation for months. `api/v1/handlers.go:40` is what a history agent writes
// when it found nothing and answered anyway — the sink it was handed, not a fix
// — and it took the finding out terminally, with SKILL.md relaying "RETRACTED —
// already fixed by api/v1/handlers.go:40" to a reader who cannot look that up.
// A unit assertion on the predicate cannot show the discard; only running the
// script can, so the end-to-end direction is pinned here as well as at the
// predicate.
test('a file:line masquerading as an upstream fix does not retract the finding', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      history: { ...UNFIXED, fixed: 'YES', complete: true, reference: 'api/v1/handlers.go:40' },
    }),
  })
  assert.notEqual(result.status, 'ALREADY_FIXED')
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.doesNotMatch(String(result.reason || ''), /already fixed/)
})

// The other direction, in the same shape, because a fix that stops retracting is
// as expensive as one that retracts wrongly: it reports a dead bug as live. This
// is what says the branch above narrowed the predicate rather than disabling it.
test('a real cited fix still retracts', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      history: { ...UNFIXED, fixed: 'YES', complete: true, reference: 'fixed in v1.4.0', evidence: 'released upstream' },
    }),
  })
  assert.equal(result.status, 'ALREADY_FIXED')
  assert.match(result.reason, /already fixed by fixed in v1\.4\.0/)
})

// The same predicate as `api/v1/handlers.go:40` above, the other way round: a
// real distro advisory that FIXED the bug, refused because the allowlist had not
// been told the registry's name. A unit assertion on the predicate does not show
// what that costs — only running the script does, and it came back
// TRUE_POSITIVE, which SKILL.md relays as "BUG #N TRUE POSITIVE" on a bug that
// was already dead.
test('a distro advisory retracts the finding it fixed', async () => {
  for (const reference of ['RHSA-2021:4056', 'SUSE-SU-2021:1234', 'MFSA-2021-24', '!412']) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({
        history: { ...UNFIXED, fixed: 'YES', complete: true, reference, evidence: 'released upstream' },
      }),
    })
    assert.equal(result.status, 'ALREADY_FIXED', reference)
    assert.ok(result.reason.includes(reference), reference)
  }
})

// And the route left open for a registry the allowlist STILL does not know. An
// allowlist is incomplete by construction, so the gate agent is the only party
// who can catch the next miss — and it can only do that if it is handed the
// string. `reference` reaches no prompt of its own; the downgrade note is its
// only carrier, and that note used to deny the reference existed.
test('an unrecognised reference reaches the gate agent rather than being denied', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      history: { ...UNFIXED, fixed: 'YES', complete: true, reference: 'ACME-SA-alpha', evidence: 'vendor bulletin' },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  const gate = calls.find((c) => c.label === 'gates')
  assert.ok(gate.prompt.includes('ACME-SA-alpha'), 'the gate agent must be handed the reference it has to check')
  assert.doesNotMatch(gate.prompt, /with no commit, PR, issue or advisory reference/)
})

// The finding's own repro, end to end: the predicate assertions cannot show the
// terminal status, and the terminal status is what this cost. Case-exactly,
// `Yes` with a real commit sha shipped an already-fixed bug as TRUE_POSITIVE at
// the agent's severity, with the word "fixed" nowhere in the result.
test('a cited fix retracts whatever case the history agent answered in', async () => {
  for (const answer of ['Yes', 'yes', ' YES ']) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({
        history: {
          ...UNFIXED,
          fixed: answer,
          complete: true,
          reference: 'torvalds/linux@a1b2c3d',
          evidence: 'the caller now digests',
        },
      }),
    })
    assert.equal(result.status, 'ALREADY_FIXED', answer)
    assert.match(result.reason, /already fixed by torvalds\/linux@a1b2c3d/)
  }
})

// The downgrade has no terminal status of its own, so the prompt is the only
// place it is observable — and the prompt is the only place it MATTERS, since a
// gate agent told `Already-fixed search: Yes` cannot tell an unproven retraction
// from a proven one.
test('an uncited fix reaches the gate prompt as UNCERTAIN, not as the case it arrived in', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      history: { ...UNFIXED, fixed: 'Yes', complete: true, reference: '', evidence: 'it felt familiar' },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE', 'an uncited retraction must still not discard a live finding')
  const gates = calls.find((c) => c.label === 'gates')
  assert.ok(gates, 'the six-gate review must run')
  assert.match(gates.prompt, /Already-fixed search: UNCERTAIN/)
  assert.match(gates.prompt, /a retraction has to point at something/)
})

// --------------------------------------------------------------- triage-poc
//
// Build and review are one script, so a test that scripts only the builder runs
// on into the challenges and the report. Every fixture here therefore supplies
// the whole chain, and the build-phase assertions are about which agents were
// dispatched rather than about the status the build alone produced.

const BUILD_ARGS = {
  baseDir: BASE,
  finding: { summary: 'negative amount reverses a transfer', sink: 'ledger.py:12' },
  verification: {
    status: 'TRUE_POSITIVE',
    impact: { impact: 'drains', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
    history: { fixed: 'NO', searched: 'git log -p -- ledger.py, issues' },
  },
  envelope: { hosts: [], level: 1, destructive: false },
  candidates: [
    { name: 'a', description: 'direct call', entryPoint: 'transfer', payload: '-500' },
    { name: 'b', description: 'via api', entryPoint: 'api', payload: '-500' },
  ],
}

const BUILT_POC = {
  built: true,
  executed: true,
  lintPassed: true,
  pocType: 'standalone',
  path: 'poc/x.py',
  absolutePath: '/wt/poc/x.py',
  command: 'python3 /wt/poc/x.py',
  output: 'AssertionError: alice went negative',
  invokedSymbol: 'ledger.transfer',
}

test('an acceptable build stops retrying and goes straight to the reviewers', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(
    calls.filter((c) => c.label.startsWith('build:')).length,
    1,
    'a successful first attempt must not retry',
  )
  assert.ok(calls.some((c) => c.label === 'artifact-check'))
})

test('a build that failed lint is retried, not accepted', async () => {
  let attempt = 0
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      build: () => (attempt++ === 0 ? { ...BUILT_POC, lintPassed: false } : BUILT_POC),
    }),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(
    calls.filter((c) => c.label.startsWith('build:')).length,
    2,
    'the first attempt must be rejected and retried',
  )
})

test('every attempt failing returns BUILD_FAILED, bounded by the cap', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: { build: { ...BUILT_POC, built: false, failureReason: 'no path' } },
  })
  assert.equal(result.status, 'BUILD_FAILED')
  assert.equal(calls.length, 2, 'MAX_ATTEMPTS bounds the retry loop')
})

// POC_SCHEMA requires these four, and `required` checks presence, not content:
// `output: '   '` is schema-valid. Bare truthiness accepted it, so a builder
// reporting whitespace returned BUILT and that whitespace reached all five
// challenge prompts as the "Captured output" the reviewers judge — and reached
// review-poc's lint command as `--symbol '  '`.
test('a whitespace-only build is rejected, not reported as BUILT', async () => {
  for (const field of ['absolutePath', 'command', 'output', 'invokedSymbol']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: { build: { ...BUILT_POC, [field]: '   ' } },
    })
    assert.equal(result.status, 'BUILD_FAILED', `whitespace ${field} must not pass the gate`)
    assert.ok(result.reason && result.reason.trim())
  }
})

// And the failure's own explanation gets the same treatment, for the same reason:
// `failureReason: '   '` is schema-valid, it is truthy, and it was taken verbatim.
// It becomes BUILD_FAILED's `reason` — which SKILL.md tells the orchestrator to
// relay as the missing fact — and the retry prompt's "Why it failed:", so a second
// attempt is told nothing about the first.
test('a whitespace failureReason falls back rather than becoming the reason', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: { build: { ...BUILT_POC, built: false, failureReason: '   ' } },
  })
  assert.equal(result.status, 'BUILD_FAILED')
  assert.ok(result.reason && result.reason.trim(), 'BUILD_FAILED must explain itself')
  const retry = calls.filter((c) => c.label.startsWith('build:'))[1]
  assert.ok(retry, 'the second attempt must run')
  assert.ok(
    !/Why it failed:\s*\n/.test(retry.prompt),
    'the retry must be told something about the first attempt',
  )
})

test('no candidates returns NO_CANDIDATES without throwing', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, candidates: [] },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'NO_CANDIDATES')
  assert.equal(calls.length, 0)
})

test('a forwarded failed verification never reaches the builder', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, verification: { ...BUILD_ARGS.verification, status: 'NOT_EXPLOITABLE' } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0)
})

test('a destructive envelope above level 2 never reaches the builder', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, envelope: { hosts: [], level: 4, destructive: true } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0, 'the safety contradiction must be caught before an agent runs')
})

// ------------------------------------------------- triage-poc, review half

const CLEAN_ARTIFACT = { fileExists: true, lintExitZero: true, reimplementation: 'NOT_DEFINED', reRun: 'REPRODUCED', reRunNotes: '', evidence: 'ok' }
const rebutted = (key) => ({ challenge: `c:${key}`, rebuttal: 'r', winner: 'REBUTTAL', evidence: 'e' })
const REPORT = {
  severity: 'High',
  severityRationale: 'internal root cause',
  reportPath: '/wt/poc/finding.md',
  unproven: 'no network route was exercised',
}

// The build is scripted too: the reviewers judge whatever the builder returned,
// and BUILT_POC is what supplies the absolutePath and invokedSymbol the artifact
// prompt interpolates. When these were two workflows a `poc` arg stood in for it,
// and that fixture could — and did — carry fields no builder had produced.
const reviewAgents = (over = {}) => ({
  build: BUILT_POC,
  'artifact-check': CLEAN_ARTIFACT,
  challenge: (prompt) => rebutted(prompt.slice(0, 8)),
  report: REPORT,
  ...over,
})

test('five rebuttals and a clean artifact returns REPORTED at HIGH', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(result.band.label, 'HIGH')
})

// Principle 5 — "call real code, never reimplement" — is re-checked exactly
// once by someone who did not build the PoC, and only by poc-lint's --symbol
// rule. Deleting the whole `--symbol '...'` argument from the prompt left 121
// node and 65 pytest assertions green, so nothing covered the one command that
// makes the independent reviewer independent.
test('the artifact prompt re-runs poc-lint with the real symbol', async () => {
  const { calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  const artifact = calls.find((c) => c.label === 'artifact-check')
  assert.ok(artifact, 'the artifact check must be dispatched')
  assert.ok(
    artifact.prompt.includes(`--symbol '${BUILT_POC.invokedSymbol}'`),
    `the Principle 5 re-check is missing its symbol; prompt said: ${
      artifact.prompt.split('\n').find((l) => l.includes('poc-lint.sh'))
    }`,
  )
  assert.ok(
    artifact.prompt.includes(`'${BUILT_POC.absolutePath}'`),
    'and it must lint the file the builder actually wrote',
  )
})

// The linter cannot decide Principle 5 and the enum has to, so the two clearing
// values must be exclusive of the case the linter misses: a copy pasted under a
// DIFFERENT name. Rule 6 keys on the leaf, so it prints no note; rule 8 greps the
// whole file, so a mention in a comment satisfies it — and the reviewer, asked
// whether the PoC "does not define <symbol> at all", answered NOT_DEFINED
// truthfully and cleared a pasted copy. The question has to be about the LOGIC
// under any name, or the builder prompt's "renaming past the note buys nothing"
// is false.
test('the artifact prompt asks about a copy under ANY name, not about the symbol name', async () => {
  const { calls } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents() })
  const artifact = calls.find((c) => c.label === 'artifact-check')
  assert.ok(artifact, 'the artifact check must be dispatched')
  assert.match(artifact.prompt, /under ANY name/, 'NOT_DEFINED must not be satisfiable by a rename')
  assert.match(artifact.prompt, /A copy under a DIFFERENT name is this/, 'COPY_OF_TARGET must claim the renamed case')
  // and `evidence` is asked for on every answer, because artifactProblem now
  // trims it on the clearing path too
  assert.match(artifact.prompt, /whichever of the three you answer/)
})

// checkpoints: the PREFERRED PoC type is test-integrated, and the builder prompt
// requires such a PoC to FAIL while the vulnerability exists. Step 4 asked the
// reviewer to "report whether it reproduces the impact" and said nothing about
// that, so a red test read as a PoC that did not reproduce and the report
// recorded a boundary in `unproven` that was not one.
test('the artifact prompt tells the reviewer a red test-integrated PoC is a reproduction', async () => {
  const { calls } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents() })
  const artifact = calls.find((c) => c.label === 'artifact-check')
  assert.match(artifact.prompt, /Grade the impact, not the exit code/)
  assert.match(artifact.prompt, /test-integrated/, 'and it must name the type the rule applies to')
})

// poc-lint.sh exits 2 on an empty --symbol rather than skipping the real-code
// check silently, so a PoC without the field does not weaken the review — it
// breaks it, and returns a BLOCKED that blames the builder's lintPassed claim.
// The build gate is what stops it: a builder that omits invokedSymbol never
// produces a PoC, so no reviewer is ever spent on one.
test('a build with no invokedSymbol never reaches a reviewer', async () => {
  for (const bad of [undefined, '', '   ']) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ build: { ...BUILT_POC, invokedSymbol: bad } }),
    })
    assert.equal(result.status, 'BUILD_FAILED', `invokedSymbol ${JSON.stringify(bad)} must fail the gate`)
    assert.ok(
      !calls.some((c) => c.label === 'artifact-check'),
      'no reviewer may be spent on a PoC that cannot be lint-checked',
    )
  }
})

test('a lint failure found by the reviewer blocks, whatever the builder said', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': { ...CLEAN_ARTIFACT, lintExitZero: false, lintOutput: 'stub-body' },
    }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /poc-lint/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'no report for an unverified artifact')
})

test('a missing PoC file blocks', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ 'artifact-check': { ...CLEAN_ARTIFACT, fileExists: false } }),
  })
  assert.equal(result.status, 'BLOCKED')
})

// The off-type shapes reached REPORTED at HIGH — TRUE POSITIVE with a severity —
// on a PoC with no file, or one whose lint failed, because both were read by
// truthiness and every one of these strings is truthy.
test('an off-type artifact boolean blocks instead of reaching REPORTED', async () => {
  for (const check of [
    { ...CLEAN_ARTIFACT, lintExitZero: 'no' },
    { ...CLEAN_ARTIFACT, lintExitZero: 1 },
    { ...CLEAN_ARTIFACT, fileExists: 'false' },
  ]) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ 'artifact-check': check }),
    })
    assert.equal(result.status, 'BLOCKED', JSON.stringify(check))
    assert.ok(!calls.some((c) => c.label === 'report'), 'a report was written on an unverified artifact')
  }
})

test('an off-type build boolean fails the build rather than buying five reviewers', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ build: { ...BUILT_POC, built: 'no', failureReason: 'nothing was built' } }),
  })
  assert.equal(result.status, 'BUILD_FAILED')
  assert.ok(!calls.some((c) => c.label === 'artifact-check'), 'a reviewer was paid for a build that did not happen')
})

// The prompt half of the same defect, which no behavioural test can reach: the
// field is a boolean and the prompt asked for an exit code, so a reviewer
// complying literally after a CLEAN run reported 0 and blocked a good PoC.
test('the artifact prompt asks for a boolean, not the exit code', async () => {
  const { calls } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents() })
  const prompt = calls.find((c) => c.label === 'artifact-check').prompt
  assert.ok(!prompt.includes('Report its exit code as lintExitZero'), 'the prompt still asks for the exit code')
  assert.match(prompt, /lintExitZero TRUE if it exited 0/)
  assert.match(prompt, /It is a boolean, not the exit code/)
})

// End to end, because the unit test on `artifactProblem` cannot show that a
// reimplementation verdict actually ends the stage. poc-lint.sh reports the
// candidate as a NOTE and exits 0 — grep cannot tell a façade re-export from a
// copy — so five defeated challenges and a lint-clean re-run are exactly the
// state this arrives in, and before the verdict field existed it came back
// REPORTED on a PoC proving only that a copy is broken.
test('a reviewer finding the code under test copied into the PoC blocks', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': { ...CLEAN_ARTIFACT, reimplementation: 'COPY_OF_TARGET', evidence: 'parse_request pasted from target/parser.py:47' },
    }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /reimplements the code under test/)
  assert.match(result.reason, /parser\.py:47/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'a copy is not written up')
})

test('a lost already-fixed challenge overrides the band', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: 'commit 99a4704', complete: true, evidence: 'the fix landed one layer up' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'ALREADY_FIXED')
  assert.match(result.reason, /already-fixed/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'a patched bug is not written up')
})

// A dead challenge-4 agent searched nothing, so it cited nothing, so it retracts
// nothing: `ALREADY_FIXED` is a claim that a fix exists and SKILL.md relays it
// with the reference. It used to fire here, discarding a built, executed,
// lint-clean finding on a status with no evidence behind it — the same
// unreferenced retraction triage-static refuses at `fixed: YES` with no
// reference. The missing verdict is still counted against the finding: 4/5 is
// MEDIUM, and the report has to address the challenge nobody answered.
test('a dead challenge-4 agent costs a band step rather than retracting the finding', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) => (prompt.includes('ALREADY FIXED') ? null : rebutted('x')),
    }),
  })
  assert.notEqual(result.status, 'ALREADY_FIXED')
  assert.equal(result.defeated, 4)
  assert.equal(result.band.label, 'MEDIUM')
  const report = calls.find((c) => c.label === 'report')
  assert.ok(report, 'a MEDIUM band still writes the report')
  assert.match(report.prompt, /already-fixed: no verdict returned/)
  // REPORTED is the only terminal status reachable WITH a challenge still
  // standing, and it was the only one omitting `unrebutted` — so the standing
  // challenge appeared in the report FILE and nowhere in the answer, while
  // SKILL.md asks the orchestrator only for the band and the tally.
  assert.equal(result.status, 'REPORTED')
  assert.ok(
    (result.unrebutted || []).some((u) => u.key === 'already-fixed'),
    'REPORTED must name the challenge that is still standing',
  )
})

// The opposite hole from the one above, opened by fixing it: challenge 4 AWARDED
// on a WHOLE fix, naming it in `evidence` but citing nothing in `reference`. That
// is not a retraction — a retraction has to point at something — but it must not
// fall through to the band either, because 4/5 is MEDIUM and MEDIUM returns
// REPORTED, which SKILL.md maps to TRUE POSITIVE. An already-patched bug reported
// as live is the rounding error this plugin exists to prevent.
test('an awarded but uncited WHOLE fix is not reported as live', async () => {
  for (const reference of ['', 'n/a', 'see evidence']) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({
        challenge: (prompt) =>
          prompt.includes('ALREADY FIXED')
            ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference, complete: true, evidence: 'the fix landed one layer up' }
            : rebutted('x'),
      }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO', `reference ${JSON.stringify(reference)}`)
    assert.match(result.reason, /already-fixed/)
    assert.ok(!calls.some((c) => c.label === 'report'), 'an unestablished retraction is not written up')
  }
})

// Stage 3's copy of the same lie Stage 1's downgrade note told: a reason saying
// nothing was in `reference` while something was. The reason is what the
// orchestrator relays, so it is the only place this string reaches a reader, and
// denying it throws away exactly what the reviewer needs to settle the question.
test('an unrecognised challenge-4 reference is quoted, not denied', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: 'ACME-SA-alpha', complete: true, evidence: 'the fix landed one layer up' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /ACME-SA-alpha/)
  assert.doesNotMatch(result.reason, /with no commit, PR, issue or advisory in/)
})

// `winner` is an enum the runtime validator does not enforce — `required` is all
// it enforces — and the two readers of it graded it differently: `tallyChallenges`
// by exclusion (anything but REBUTTAL counts against the finding) and this gate
// affirmatively (`=== 'CHALLENGE'`). An off-enum spelling therefore cost the
// finding a band step AND escaped the gate: 4/5, MEDIUM, REPORTED, on a bug a
// reviewer said was entirely patched. Both read it by exclusion now.
test('an off-enum winner does not escape the uncited-fix gate', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'challenge', reference: 'n/a', complete: true, evidence: 'the fix landed one layer up' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /already-fixed/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'an unestablished retraction is not written up')
})

// And the case the gate above used to swallow. `complete: false` says the finding
// SURVIVES the fix, so the citation the retraction needed is not load-bearing
// here: checkpoints.md 5.1, the challenge-4 prompt and the failure table all
// promise this is reported with the partial fix recorded against it, and it ended
// the stage as NEEDS_MORE_INFO instead — on a bug every party agreed was live.
// Stage 1 makes the same call: `downgradeUnreferencedFix` marks an uncited fix
// claim UNCERTAIN and carries on to a full verdict rather than halting.
test('an awarded but uncited PARTIAL fix is reported, not parked', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: '', complete: false, evidence: 'the other sink is untouched' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(result.defeated, 4, 'the challenge still costs a band step')
  assert.ok(calls.some((c) => c.label === 'report'), 'a live finding is written up')
})

// The band and the artifact gate both outrank an uncited claim, and both used to
// sit behind it. A finding that lost ALL FIVE challenges is the FALSE POSITIVE
// SKILL.md maps `confidence NONE (0/5)` to, not a missing citation; and a PoC
// whose file does not exist is BLOCKED whatever challenge 4 said about it.
test('an uncited fix claim does not outrank the band or the artifact', async () => {
  const uncitedWhole = (prompt) =>
    prompt.includes('ALREADY FIXED')
      ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: '', complete: true, evidence: 'it felt familiar' }
      : { challenge: 'x', rebuttal: 'none', winner: 'CHALLENGE', reference: '', complete: false, evidence: 'x' }

  const refuted = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ challenge: uncitedWhole }),
  })
  assert.equal(refuted.result.status, 'DO_NOT_SUBMIT', '0/5 defeated is a refutation, not a missing fact')
  assert.equal(refuted.result.band.label, 'NONE')

  const noFile = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': { ...CLEAN_ARTIFACT, fileExists: false },
      challenge: (prompt) => (prompt.includes('ALREADY FIXED') ? uncitedWhole(prompt) : rebutted('x')),
    }),
  })
  assert.equal(noFile.result.status, 'BLOCKED', 'an unverifiable artifact still blocks')
})

// A CITED but PARTIAL fix is the third shape, and it retracted like a whole one:
// challenge 4's prompt asked for complete-or-partial, CHALLENGE_SCHEMA had
// nowhere to put the answer, and `alreadyFixedStands` read any cited award as a
// retraction. A demonstrated bug whose second sink is untouched then got
// ALREADY_FIXED and no report at all. Stage 1 has gated on `complete` since it
// was written; this is the same rule reaching the stage that holds the PoC.
test('a cited but PARTIAL fix is reported, not retracted', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: 'commit 99a4704', complete: false, evidence: 'the other sink is untouched' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(result.defeated, 4, 'the challenge still costs a band step')
  assert.ok(
    (result.unrebutted || []).some((u) => u.key === 'already-fixed'),
    'the partial fix is reported as still standing against the finding',
  )
  assert.ok(calls.some((c) => c.label === 'report'), 'a live finding is written up')
})

// checkpoints.md 5.1 says the already-fixed outcome "overrides everything else",
// and the artifact gate was ahead of it. The two facts are different in kind: the
// artifact check is a judgement about whether the PoC is real, and challenge 4 is a
// fact about the codebase — a fix, with a reference. A dead artifact agent or a lint
// failure therefore turned "this is already patched, retract it" into BLOCKED, which
// SKILL.md relays as NEEDS MORE INFO and whose completion gate tells the
// orchestrator to re-dispatch: paying twice to be told the same thing about a bug
// that no longer exists.
test('the already-fixed override outranks an unverifiable artifact', async () => {
  const patched = (prompt) =>
    prompt.includes('ALREADY FIXED')
      ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: 'commit 99a4704', complete: true, evidence: 'the fix landed one layer up' }
      : rebutted('x')
  const cases = [
    ['a dead artifact agent', null],
    ['a lint failure', { ...CLEAN_ARTIFACT, lintExitZero: false, lintOutput: 'stub-body' }],
    ['no PoC file', { ...CLEAN_ARTIFACT, fileExists: false }],
  ]
  for (const [label, artifact] of cases) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ 'artifact-check': artifact, challenge: patched }),
    })
    assert.equal(result.status, 'ALREADY_FIXED', label)
    assert.match(result.reason, /already-fixed/, label)
    assert.match(result.reason, /commit 99a4704/, label)
    assert.ok(!calls.some((c) => c.label === 'report'), `${label}: a patched bug is not written up`)
  }
})

// And the artifact gate keeps its precedence over everything that IS a judgement
// about the PoC: the band is only meaningful if the artifact the challenges judged
// is real.
test('an unverifiable artifact still blocks when no fix was found', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': null,
      challenge: (prompt) => (prompt.includes('ALREADY FIXED') ? rebutted('4') : null),
    }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /never independently verified/)
})

test('LOW confidence does not proceed to a report', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? rebutted('fixed')
          : { challenge: 'c', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' },
    }),
  })
  // already-fixed is rebutted so the unconditional rule does not fire; the four
  // others are lost, so 1/5 defeated lands in LOW and the band alone stops it.
  assert.equal(result.status, 'DO_NOT_SUBMIT')
  assert.equal(result.band.label, 'LOW')
  assert.equal(result.defeated, 1)
  assert.ok(!calls.some((c) => c.label === 'report'))
})

// `status`, `reason`, `band` and `defeated` were byte-identical between "five
// reviewers refuted it" and "five agents never ran". SKILL.md keys its FALSE
// POSITIVE row on that exact reason prefix, so a built, executed, lint-clean,
// independently artifact-checked PoC of a real bug was reported as refuted by
// reviewers who never ran. The only difference in the whole return was
// `unrebutted[].challenge`, and nothing told the orchestrator to read it.
test('challenge agents that never ran are not reported as reviewers who refuted it', async () => {
  const silent = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents({ challenge: null }) })
  assert.equal(silent.result.status, 'NEEDS_MORE_INFO', 'silence is a missing fact, not a refutation')
  assert.equal(silent.result.band.label, 'NONE', 'the band still counts silence against the finding')
  assert.match(silent.result.reason, /no verdict/i, 'the reason has to name what is missing')
  assert.ok(
    !silent.result.reason.startsWith('confidence NONE (0/5 defeated)'),
    'the reason still opens with the prefix SKILL.md maps to FALSE POSITIVE',
  )

  const refuted = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: { challenge: 'c', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'the guard rejects it' },
    }),
  })
  assert.equal(refuted.result.status, 'DO_NOT_SUBMIT', 'five arguing reviewers still refute')
  assert.ok(
    refuted.result.reason.startsWith('confidence NONE (0/5 defeated)'),
    'the FALSE POSITIVE row of SKILL.md keys on this prefix and must stay reachable',
  )
  assert.notEqual(silent.result.status, refuted.result.status, 'the two must differ without reading the reason')
})

// Wider than all-five-dead: any mix landing the band at NONE with one silent
// agent rested partly on silence and produced the same FALSE-POSITIVE-keyed
// prefix. The per-key override MUST be the label key `challenge:real-deployment`
// — a `prompt.includes('REAL DEPLOYMENT')` predicate does not match the prompt
// text and silently makes the fixture a no-op.
test('a single silent agent stops a 0/5 band from reading as a refutation', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: { challenge: 'c', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' },
      'challenge:real-deployment': null,
    }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /real-deployment/, 'the reason names the agent to re-run')
  assert.equal(result.defeated, 0)
  assert.ok(!calls.some((c) => c.label === 'report'), 'nothing is written up on an incomplete review')
})

// The finding's own repro, end to end, because the unit assertions cannot show
// what it cost: nothing in code required the PoC to reproduce for anyone but its
// builder, so a build that passed `isAcceptableBuild`, five defeated challenges
// and a clean artifact check came back REPORTED at High — TRUE POSITIVE, per
// SKILL.md — while the one independent reader who ran the exploit reported the
// balance unchanged. Every challenge prompt interpolates the BUILDER's captured
// output, so the five could not have caught it.
test('a PoC the reviewer could not reproduce does not come back REPORTED', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': {
        ...CLEAN_ARTIFACT,
        reRun: 'DID_NOT_REPRODUCE',
        reRunNotes: 'ran it; the balance is unchanged',
      },
    }),
  })
  assert.equal(result.status, 'BLOCKED', 'a PoC that demonstrates nothing is a fact to settle, not a report')
  assert.match(result.reason, /did not reproduce the impact/)
  assert.ok(result.poc, 'the artifact is named so it can be corrected')
})

// And the direction that must not regress into a false dismissal. A testnet or
// service-dependent PoC can legitimately have nowhere to run on the reviewer's
// host; the band still decides and the report records the boundary.
test('a PoC the reviewer had no environment for still reports', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': {
        ...CLEAN_ARTIFACT,
        reRun: 'COULD_NOT_RUN_HERE',
        reRunNotes: 'no ES cluster on this host',
      },
    }),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(result.band.label, 'HIGH')
})

test('a severity above the cap for an integration root cause blocks the report', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: {
      ...BUILD_ARGS,
      verification: {
        ...BUILD_ARGS.verification,
        impact: { impact: 'drains', rootCause: 'integration', classification: 'vulnerability' },
      },
    },
    agents: reviewAgents({ report: { ...REPORT, severity: 'Critical' } }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /Medium cap/)
})

test('an empty unproven field fails checkpoint 6.1', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ report: { ...REPORT, unproven: '   ' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /unproven/)
})

// The prompt says "reportPath must be a file you actually wrote, not a path you
// intend to use", and a prompt is a request the model may decline. Nothing gated
// the content: `reportPath: ''` returned REPORTED with no report to point at,
// and the 5.2 block message below rendered as "The report at  carries a
// severity...".
test('an empty reportPath fails checkpoint 6.1', async () => {
  for (const reportPath of ['', '   ']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ report: { ...REPORT, reportPath } }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO', `reportPath ${JSON.stringify(reportPath)} must not pass`)
    assert.ok(result.reason && result.reason.trim(), 'a halt must explain itself')
    assert.match(result.reason, /reportPath/)
  }
})

// The severity cap message interpolates report.reportPath, so 6.1 has to run
// first — otherwise the block that tells the user where to correct the severity
// names no file.
test('an empty reportPath is caught before the severity cap names it', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: {
      ...BUILD_ARGS,
      verification: {
        ...BUILD_ARGS.verification,
        impact: { impact: 'drains', rootCause: 'integration', classification: 'vulnerability' },
      },
    },
    agents: reviewAgents({ report: { ...REPORT, severity: 'Critical', reportPath: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.doesNotMatch(result.reason, /The report at\s{2}/)
})

test('a blank severityRationale fails checkpoint 5.2', async () => {
  // Checkpoint 5.2 passes on "the rating is supported by evidence". unproven and
  // reportPath were both trimmed on that reasoning and this one was not, so a
  // Medium asserted with nothing behind it returned REPORTED — and the severity
  // cap below only inspects Critical and High, so nothing else looked.
  for (const severityRationale of ['', '   ']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ report: { ...REPORT, severity: 'Medium', severityRationale } }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO')
    assert.match(result.reason, /severityRationale/)
  }
})

// The report prompt was the one stage nothing asserted on. Four separate
// mutations to it — emptying `corrections`, hardcoding the re-run status, and
// deleting either caveat — left the whole suite green. `impactCorrection` is
// the worst of them: it is the channel by which a reviewer's "the true impact
// is weaker than claimed" reaches the report, which is the inflated-impact
// failure this skill exists to prevent.
const reportPrompt = async (over) => {
  const { calls } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents(over) })
  const call = calls.find((c) => c.label === 'report')
  assert.ok(call, 'the report agent must be dispatched')
  return call.prompt
}

test("a reviewer's impact correction reaches the report agent", async () => {
  const prompt = await reportPrompt({
    challenge: (p) => ({
      ...rebutted(p.slice(0, 8)),
      impactCorrection: p.includes('Challenge 2') ? 'recovery caps this at one 500' : undefined,
    }),
  })
  assert.match(prompt, /recovery caps this at one 500/)
})

test('a re-run the reviewer could not reproduce is stated, not glossed', async () => {
  const failed = { ...CLEAN_ARTIFACT, reRun: 'COULD_NOT_RUN_HERE', reRunNotes: 'no ES cluster here' }
  const prompt = await reportPrompt({ 'artifact-check': failed })
  assert.match(prompt, /no ES cluster here/)
  assert.match(prompt, /unproven/)

  // And the passing case must not claim the boundary exists.
  assert.doesNotMatch(await reportPrompt({}), /could not run this PoC here/)
})

test('MEDIUM confidence tells the report to document the uncertainties', async () => {
  // Three of five defeated is MEDIUM, which proceeds only with the uncertainties
  // written down. Deleting that instruction changed no assertion.
  const prompt = await reportPrompt({
    challenge: (p) =>
      /Challenge (1|5)\./.test(p)
        ? { challenge: 'unrebutted', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' }
        : rebutted(p.slice(0, 8)),
  })
  assert.match(prompt, /Confidence is MEDIUM/)
  assert.match(prompt, /False Positive Analysis section must document the uncertainties/)
})

// ------------------------------------------------------- the dispatch contract

test('a workflow dispatched with no args at all returns BLOCKED, not a TypeError', async () => {
  // The top-of-script destructure ran before missingArgs, so `args` undefined —
  // a mistyped `arg:`, or an omitted block — killed the run with
  // "Cannot destructure property 'baseDir'" and no status came back at all.
  // Every `a && a.finding` guard inside the validators exists for this input
  // and none of them was reachable.
  for (const file of ['triage-static.js', 'triage-poc.js', 'triage-poc.js']) {
    for (const args of [undefined, null]) {
      const { result, calls } = await runScript(file, { args })
      assert.equal(result.status, 'BLOCKED', `${file} with args=${args}`)
      assert.ok(result.reason && result.reason.trim(), `${file} must say why`)
      assert.equal(calls.length, 0, `${file} must not spend an agent`)
    }
  }
})

// `DO_NOT_SUBMIT` used to carry three outcomes at once, and the documented mapping
// sent all three to FALSE POSITIVE. Two of them were the rounding error this plugin
// exists to prevent: an already-fixed retraction (the bug was REAL) and an
// incomplete report (nothing was disproven at all). They are three statuses now,
// and this pins each to its own — the orchestrator no longer has to pattern-match a
// reason prefix to tell them apart.
test('the three Stage 3 refusals are three distinct statuses', async () => {
  const cases = [
    [
      'ALREADY_FIXED',
      reviewAgents({
        challenge: (prompt) =>
          prompt.includes('ALREADY FIXED')
            ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', reference: 'commit 99a4704', complete: true, evidence: 'the fix landed one layer up' }
            : rebutted('x'),
      }),
    ],
    [
      'DO_NOT_SUBMIT',
      reviewAgents({
        challenge: (prompt) =>
          prompt.includes('ALREADY FIXED')
            ? rebutted('fixed')
            : { challenge: 'c', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' },
      }),
    ],
    ['NEEDS_MORE_INFO', reviewAgents({ report: { ...REPORT, unproven: '' } })],
  ]
  const seen = new Set()
  for (const [expected, agents] of cases) {
    const { result } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents })
    assert.equal(result.status, expected)
    assert.ok(result.reason && result.reason.trim(), `${expected} must explain itself`)
    seen.add(result.status)
  }
  assert.equal(seen.size, 3, 'all three must be distinguishable without reading the reason')
})

// REPORTED was the one terminal status with no `reason`, while SKILL.md's
// Completion Gate tells the orchestrator to relay it verbatim for every status.
//
// And with no top-level `severity`, which Stage 1 and Stage 2 both surface:
// SKILL.md tells the orchestrator to state the verdict "with the severity", so
// it read `undefined` and reported a TRUE POSITIVE carrying no severity at all.
// The number existed only at `report.severity`, which nothing names.
test('REPORTED carries a reason and a severity like every other terminal status', async () => {
  const { result } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents() })
  assert.equal(result.status, 'REPORTED')
  assert.ok(result.reason && result.reason.trim(), 'REPORTED must carry a reason')
  assert.equal(result.reason, REPORT.severityRationale)
  assert.equal(result.severity, REPORT.severity)
})
