import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { loadFn, loadFns, script } from './extract.mjs'

const STATIC = script('triage-static.js')
// decideGate calls upstreamFixStands, so the two are extracted into one scope.
// Evaluating decideGate alone made every call a ReferenceError, and the
// alternative — inlining the fix check at both call sites — is the duplicated
// gate logic this suite exists to catch.
// `fixedAnswer` for the same reason one level down: `upstreamFixStands` calls it.
// `auditedSearch` for the same reason again: `decideGate` reads the layers
// declaration through it.
const { decideGate } = loadFns(STATIC, 'decideGate', 'upstreamFixStands', 'citedReference', 'fixedAnswer', 'auditedSearch')
// `externalRootCause` alongside it, for the same reason: the precondition gate
// reads root cause through the predicate the cap reads it through.
const { missingPrecondition } = loadFns(STATIC, 'missingPrecondition', 'externalRootCause')

const layer = (name, verdict) => ({ layer: name, location: `${name}.go:10`, verdict })
const inScope = { inScope: 'YES', byDesign: false, evidence: 'in scope' }
const checked = { recoveryExists: false, effectiveImpact: 'process exits', evidence: 'no recover in the stack' }
// The already-fixed search ran and found nothing, which is the case every
// pre-existing assertion here was written under. `unfixed` is deliberately not
// a default parameter in decideGate: a caller that forgets it must fail, not
// silently assert that nothing was ever fixed.
const unfixed = { fixed: 'NO', reference: '', searched: 'git log -p, issues, CHANGELOG', evidence: 'nothing found' }

test('extract helper fails loudly when the function is absent', () => {
  assert.throws(() => loadFn(STATIC, 'noSuchFunction'), /not found/)
})

// `^function` is matched with the `m` flag, and `.match()` returns the EARLIEST
// hit. A commented-out copy of a helper therefore shadowed the real definition
// and these tests graded the comment: breaking confidenceBand to always return
// HIGH, with a correct copy left in a `/* ... */` above it, kept all 32
// assertions in review.test.mjs green.
test('a commented-out copy does not shadow the real definition', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cp-extract-'))
  const file = join(dir, 'shadow.js')
  writeFileSync(
    file,
    [
      '/* The correct version, kept for reference:',
      'function pick(n) {',
      "  return 'REAL'",
      '}',
      '*/',
      'function pick(n) {',
      "  return 'BROKEN'",
      '}',
      '',
    ].join('\n'),
  )
  assert.equal(loadFn(file, 'pick')(1), 'BROKEN', 'must extract the live definition, not the comment')
  rmSync(dir, { recursive: true, force: true })
})

test('two live definitions are a hard stop, not a first-wins guess', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cp-extract-'))
  const file = join(dir, 'dup.js')
  writeFileSync(file, "function pick(n) {\n  return 'A'\n}\nfunction pick(n) {\n  return 'B'\n}\n")
  assert.throws(() => loadFn(file, 'pick'), /defined 2 times/)
  rmSync(dir, { recursive: true, force: true })
})

test('all layers passable and threat model clear proceeds', () => {
  const r = decideGate([layer('auth', 'PAYLOAD_REACHES_SINK'), layer('bounds', 'PAYLOAD_REACHES_SINK')], checked, inScope, unfixed, 2)
  assert.equal(r.status, 'PROCEED')
})

test('a blocking layer is NOT_EXPLOITABLE and names where', () => {
  const r = decideGate([layer('auth', 'PAYLOAD_REACHES_SINK'), layer('validate', 'PAYLOAD_STOPPED_HERE')], checked, inScope, unfixed, 2)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
  assert.match(r.reason, /validate/)
})

test('a stopped payload wins over UNCERTAIN — the stronger verdict decides', () => {
  const r = decideGate([layer('a', 'UNCERTAIN'), layer('b', 'PAYLOAD_STOPPED_HERE')], checked, inScope, unfixed, 2)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
})

// NEEDS_MORE_INFO, not BLOCKED. BLOCKED means the analysis could not be RUN —
// a contract violation, a dead agent — and NEEDS_MORE_INFO means it ran and the
// evidence does not decide. An UNCERTAIN layer is the second: the code was read
// and could not be traced. Calling that BLOCKED sends the reader to the harness
// instead of to the code.
test('any UNCERTAIN layer needs more info: checkpoint 2.2 requires zero', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK'), layer('b', 'UNCERTAIN')], checked, inScope, unfixed, 2)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /unresolved/)
})

// The gate reads PAYLOAD_REACHES_SINK rather than "not stopped and not
// UNCERTAIN". Grading by
// exclusion made PROCEED the fall-through for any verdict the script does not
// recognise — on the checkpoint the phase map calls MOST CRITICAL, and the only
// gate in this pipeline that did not read the value it wanted.
test('a verdict outside the enum blocks rather than falling through to PROCEED', () => {
  for (const verdict of [undefined, '', 'passes', 'BANANA']) {
    const r = decideGate([{ layer: 'a', location: 'a.py:1', verdict }], checked, inScope, unfixed, 1)
    assert.equal(r.status, 'BLOCKED', `verdict ${JSON.stringify(verdict)} must not PROCEED`)
    assert.match(r.reason, /no PAYLOAD_REACHES_SINK verdict/)
  }
})

// Same shape, on checkpoint 3.1, whose stated rule is "Ambiguous means
// UNCERTAIN, not YES". Testing only for NO and UNCERTAIN implemented the
// opposite: anything else became YES.
test('an inScope value outside the enum does not fall through to being read as YES', () => {
  for (const value of [undefined, '', 'yes', 'MAYBE']) {
    const threat = { inScope: value, byDesign: false, evidence: 'e' }
    const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, threat, unfixed, 1)
    assert.equal(r.status, 'NEEDS_MORE_INFO', `inScope ${JSON.stringify(value)} must not PROCEED`)
  }
})

// The bug this function was extracted to expose. Before the refactor the gate
// filtered for stopped and UNCERTAIN over an empty array, matched neither, and
// fell through to PROCEED — reporting success having verified nothing.
test('every layer agent dying blocks rather than proceeding', () => {
  const r = decideGate([], checked, inScope, unfixed, 3)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /returned nothing/)
})

test('a partial layer-agent failure blocks', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, inScope, unfixed, 3)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /2 layer agent/)
})

// The same bug class one level up, and the one the old assertion here got
// wrong. It read 2.2's "at least 1 layer (or confirmed none exist)" as licence
// to PROCEED on an empty list — but nothing confirms none exist when no agent
// ran. `layers` defaults to [] in the destructure, so a dispatch that simply
// omitted the field was indistinguishable from a deliberate claim, and both
// returned "attack path verified" having dispatched zero agents against the
// checkpoint the phase map marks MOST CRITICAL.
test('zero dispatched layers and no declaration blocks: 2.2 cannot pass on zero evidence', () => {
  const r = decideGate([], checked, inScope, unfixed, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /no validation layers were inspected/)
})

// The other half of the same checkpoint — "or confirmed none exist" — which was
// unreachable while the only way to say it was to invent a layer. The 2.3.0 probe
// measured what that cost: the orchestrator sent the absence of a check AS a
// layer, exactly as the old message instructed, and the agent asked to rule on it
// returned the stopping verdict with a reason stating it meant the opposite.
test('zero layers WITH a declaration proceeds: that is 2.2 "or confirmed none exist"', () => {
  const r = decideGate([], checked, inScope, unfixed, 0, 'read charge.py, rates.py, ledger.py; no sign or bounds check anywhere on the path')
  assert.equal(r.status, 'PROCEED', 'an audited "nothing validates this path" must reach the impact agent and the severity cap')
})

// CHANGED, and the old comment here was the clearest statement of the defect: it
// claimed "anything that is not a real statement leaves the vacuous pass exactly
// where it was", which was false. `n/a` is not a real statement and it DID pass,
// because non-blankness was the whole rule. The rule is now `auditedSearch` — the
// declaration must name a file that was read — and it is read through the same
// helper the arg validator reads it through, so the two cannot disagree about
// which dispatches reach a verdict.
test('a declaration that names nothing read is still the vacuous pass', () => {
  for (const declared of [
    undefined, null, '', '   ', 0, 1, true, {}, ['charge.py'],
    'n/a', 'N/A', 'none', 'TBD', '.', '-', 'x', 'unknown', 'nothing found', 'see above',
  ]) {
    const r = decideGate([], checked, inScope, unfixed, 0, declared)
    assert.equal(r.status, 'BLOCKED', `declaration ${JSON.stringify(declared)} must not pass the gate`)
  }
})

// The declaration says nothing about layers that WERE dispatched, so it must not
// rescue a fan-out that came back short. Otherwise "I looked and found none"
// silently covers "four agents ran and one died".
test('a declaration does not excuse a layer agent that died', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, inScope, unfixed, 2, 'read everything')
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /returned nothing/)
})

test('MORE verdicts than agents dispatched blocks rather than passing', () => {
  // The results of one parallel() call are disaggregated by shape, so a
  // recovery or threat agent that volunteered a `verdict` key would be counted
  // as a layer verdict. `missing` then goes NEGATIVE, and a `> 0` check reads
  // that as "no agent is missing" while a layer agent is genuinely absent.
  // additionalProperties: false makes it unreachable; this makes it fail loudly
  // if that ever comes off.
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK'), layer('b', 'PAYLOAD_REACHES_SINK')], checked, inScope, unfixed, 1)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /mis-attributed/)
})

test('a dead recovery agent blocks: 2.3 requires recovery be checked, not assumed', () => {
  // "Checked for recovery (not assumed absent)" is the pass criterion. A null
  // from a dead agent used to fall through to the impact prompt as "not
  // established" and PROCEED — assuming absence by a different route.
  for (const dead of [undefined, null]) {
    const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], dead, inScope, unfixed, 1)
    assert.equal(r.status, 'BLOCKED')
    assert.match(r.reason, /recovery/)
  }
})

test('a dead threat-model agent blocks rather than proceeding', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, undefined, unfixed, 1)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /threat-model/)
})

// ------------------------------------------- the retraction's precedence
//
// Both outcomes retract the finding, so reordering them cannot make a false
// positive easier to report — only the REASON the orchestrator relays changes.
// And the two coincide constantly, because the usual shape of an already-fixed
// finding is a fix one layer up that a layer agent then correctly reports as
// stopped: `already-fixed`'s own fix is in `auth.py`, one layer above the reported
// `session.py:88`. Its grader asks for the commit — "the reason has to be the
// fix, cited as evidence" — and `blocked at _digest (auth.py:31)` does not carry
// it, so the better-specified of two equally-safe answers should win.
const retracted = {
  fixed: 'YES',
  complete: true,
  reference: '#412',
  searched: 'git log -p -- auth.py, CHANGELOG',
  evidence: 'the caller reduces both operands to a keyed HMAC digest',
}

test('a referenced complete fix outranks a blocking layer, and names both', () => {
  const r = decideGate([layer('digest', 'PAYLOAD_STOPPED_HERE')], checked, inScope, retracted, 1)
  assert.equal(r.status, 'ALREADY_FIXED')
  assert.match(r.reason, /#412/)
  assert.match(r.reason, /digest/, 'the blocking layer is not lost, only outranked')
  assert.match(r.reason, /Retract/)
})

// `enum` is advisory to the runtime validator, so the answer arrives in whatever
// case the agent typed. Case-exactly, `Yes` fell past this branch, past the
// downgrade that compensates for an uncited fix, and out at PROCEED — and the
// citation reaches no prompt from there, so nothing downstream could recover it.
test('a case variant of YES still outranks the blocking layer', () => {
  for (const answer of ['Yes', 'yes', ' YES ']) {
    const r = decideGate([layer('digest', 'PAYLOAD_STOPPED_HERE')], checked, inScope, { ...retracted, fixed: answer }, 1)
    assert.equal(r.status, 'ALREADY_FIXED', answer)
    assert.match(r.reason, /#412/)
  }
})

// The other direction of the citation test, and the reason it is a shape test
// rather than "contains a digit": a short sha is often all letters, and refusing
// one reports a bug that no longer exists.
test('every honest citation shape still retracts', () => {
  for (const reference of ['deadbeef', 'abcfeed', '#412', 'CVE-2024-1234', 'GHSA-jf85-cpcp-j695', 'v2.3.1', 'https://github.com/o/r/pull/412', 'fixed by 99a4704']) {
    const r = decideGate([layer('digest', 'PAYLOAD_STOPPED_HERE')], checked, inScope, { ...retracted, reference }, 1)
    assert.equal(r.status, 'ALREADY_FIXED', reference)
  }
})

// The retraction is gated on a reference existing, and nothing about promoting it
// loosens that. A fix the agent could not point at leaves the blocking layer as
// the answer.
//
// "Non-blank" was the whole test here while Stage 3's copy of the rule was
// hardened, which left the DEFAULT, ALWAYS-RUN stage retracting on `n/a` and
// SKILL.md printing `RETRACTED — already fixed by n/a`. Stage 3's challenge 4
// only runs when a PoC was asked for, so the hardened copy was the one almost
// never reached.
test('an unreferenced or partial fix does not outrank a blocking layer', () => {
  for (const history of [
    { ...retracted, reference: '' },
    { ...retracted, reference: '   ' },
    { ...retracted, reference: 'n/a' },
    { ...retracted, reference: 'unknown commit' },
    { ...retracted, reference: 'see evidence' },
    { ...retracted, reference: 'TBD' },
    { ...retracted, reference: 'not applicable' },
    // Carries a digit and cites nothing: "contains a digit" is not the test.
    { ...retracted, reference: 'see evidence at auth.py:31' },
    { ...retracted, reference: 'fixed sometime in the 2.x line' },
    // A hyphenated token carrying a digit is not an advisory ID, and a version
    // inside a FILENAME is not a version citation. One hyphen was the whole test
    // for the CVE/GHSA shape, so each of these retracted a live finding.
    { ...retracted, reference: 'fixed in a post-2020 refactor' },
    { ...retracted, reference: 'a follow-up commit, not-found-1' },
    { ...retracted, reference: 'internal-fix-2' },
    { ...retracted, reference: 'src/handlers/auth-v2.go:118' },
    { ...retracted, complete: false },
    { ...retracted, complete: undefined },
    { ...retracted, fixed: 'UNCERTAIN' },
  ]) {
    const r = decideGate([layer('digest', 'PAYLOAD_STOPPED_HERE')], checked, inScope, history, 1)
    assert.equal(r.status, 'NOT_EXPLOITABLE', JSON.stringify(history))
    assert.match(r.reason, /blocked at digest/)
  }
})

// The guard above it keeps its place: if there are more verdicts than agents
// dispatched, the results were mis-attributed and nothing read out of them is
// trustworthy — including the history verdict's position in the same array.
test('mis-attributed results still outrank a retraction', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK'), layer('b', 'PAYLOAD_REACHES_SINK')], checked, inScope, retracted, 1)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /mis-attributed/)
})

// And a dead history agent is not a silent "nothing was fixed": promoting the
// check above the liveness blocker would have made `upstreamFixStands(null)`
// fall through to the layers rather than reaching the blocker below.
test('a dead history agent still blocks rather than falling through as unfixed', () => {
  for (const dead of [undefined, null]) {
    const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, inScope, dead, 1)
    assert.equal(r.status, 'BLOCKED')
    assert.match(r.reason, /history/)
  }
})

test('a blocking layer outranks a dead recovery agent', () => {
  // Ordering matters: NOT_EXPLOITABLE is the more informative answer, and it is
  // reached without needing the recovery verdict at all.
  const r = decideGate([layer('validate', 'PAYLOAD_STOPPED_HERE')], undefined, inScope, unfixed, 1)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
})

// The same rule one level down, and the level it was NOT applied at. The
// missing-agent count was read before the stopped-payload filter, so a dead SIBLING LAYER
// agent turned a definitive NOT_EXPLOITABLE into BLOCKED — "could not determine" —
// exactly the answer-discarding the recovery ordering above exists to prevent.
// The layers are conjunctive: `decideGate` requires all of them to PASS, so one
// that stops the payload makes the sink unreachable whatever the dead one would have said.
test('a blocking layer outranks a dead sibling LAYER agent', () => {
  const r = decideGate([layer('validate', 'PAYLOAD_STOPPED_HERE')], checked, inScope, unfixed, 3)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
  assert.match(r.reason, /validate/)
})

// But mis-attribution is NOT a dead agent, and it must keep its precedence: if
// there are more verdicts than agents dispatched, some verdict in the list came
// from something that is not a layer, and a stopping verdict read out of that list could
// dismiss a live finding. Unverifiable evidence outranks a definitive-looking
// verdict built from it.
test('mis-attributed results still outrank a stopped-payload verdict', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK'), layer('b', 'PAYLOAD_STOPPED_HERE')], checked, inScope, unfixed, 1)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /mis-attributed/)
})

// A dead layer agent with no stopping verdict to outrank it still blocks: nothing here
// weakens the missing-agent check, it only loses a tie it should never have won.
test('a dead layer agent still blocks when no sibling decided the path', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, inScope, unfixed, 2)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /1 layer agent/)
})

test('out of scope halts', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'NO', evidence: 'infra' }, unfixed, 1)
  assert.equal(r.status, 'OUT_OF_SCOPE')
})

test('ambiguous scope needs more info rather than assuming in-scope', () => {
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'UNCERTAIN', evidence: '?' }, unfixed, 1)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
})

test('by-design halts as NOT_VULNERABLE', () => {
  const threat = { inScope: 'YES', byDesign: true, byDesignIndicators: 2, evidence: 'admin escape hatch' }
  const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, threat, unfixed, 1)
  assert.equal(r.status, 'NOT_VULNERABLE')
})

// `byDesignIndicators` is collected precisely to gate the boolean, and nothing
// read it: `byDesign: true` alone returned NOT_VULNERABLE, so a function named
// `forceUpdate()` ended the analysis on one indicator — the self-reported gate
// this plugin exists to replace. validation-dimensions.md and checkpoint 3.3 both
// set the bar at two plus a search, and the captured run in tests/fixtures shows
// the split: `byDesign: true, byDesignIndicators: 1` beside evidence reading
// "Count = 1/3. Below the 'two or more' bar". Below the bar the analysis
// continues; it is a flag to check, not a verdict.
test('by-design below the two-indicator bar does not dismiss', () => {
  for (const byDesignIndicators of [undefined, 0, 1]) {
    const threat = { inScope: 'YES', byDesign: true, byDesignIndicators, evidence: 'the function is called forceUpdate' }
    const r = decideGate([layer('a', 'PAYLOAD_REACHES_SINK')], checked, threat, unfixed, 1)
    assert.equal(r.status, 'PROCEED', `byDesignIndicators ${JSON.stringify(byDesignIndicators)} must not dismiss`)
  }
})

// Every input shape below has a named test above pinning its EXACT status, so
// there is no separate "returns only known statuses" case: `equal(status,
// 'BLOCKED')` already implies membership. What those tests do not check is that
// a halt explains itself, which is what this asserts.
//
// The last two cases are the only ones that can actually fail it, and they were
// missing. Every other reason here is built from a string literal, so the loop
// could only catch a `reason` key deleted outright — which
// test_terminal_returns_carry_a_reason already catches statically, across all
// three scripts. OUT_OF_SCOPE and NOT_VULNERABLE both return
// `reason: threatVerdict.evidence`, straight from an agent, and THREAT_SCHEMA's
// `required` checks presence and not content: `evidence: ''` is schema-valid and
// yields `{status: 'OUT_OF_SCOPE', reason: ''}`. A halt with no explanation is
// what the orchestrator has to relay to the user.
test('every non-PROCEED status carries a non-empty reason', () => {
  // Every row carries the history verdict, and getting that wrong is how this
  // test stopped grading anything: the argument was added between `threat` and
  // `attemptedLayers`, so a 4-tuple put the layer count in the history slot and
  // left `attemptedLayers` undefined. `undefined - 1` is NaN, `NaN !== 0` is
  // true, and every row returned BLOCKED at the mis-attribution branch without
  // reaching the one it was written for. All ten still passed. The mutation gate
  // found it: breaking the OUT_OF_SCOPE evidence fallback changed nothing here.
  const cases = [
    [[], checked, inScope, unfixed, 0],
    [[], checked, inScope, unfixed, 3],
    [[layer('a', 'PAYLOAD_STOPPED_HERE')], checked, inScope, unfixed, 1],
    [[layer('a', 'UNCERTAIN')], checked, inScope, unfixed, 1],
    [[{ layer: 'a', location: 'a.py:1' }], checked, inScope, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], undefined, inScope, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, undefined, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, inScope, undefined, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'UNCERTAIN' }, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'NO', byDesign: false, evidence: '' }, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'NO', byDesign: false, evidence: '   ' }, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'YES', byDesign: true, byDesignIndicators: 2, evidence: '' }, unfixed, 1],
    [[layer('a', 'PAYLOAD_REACHES_SINK')], checked, { inScope: 'YES', byDesign: true, byDesignIndicators: 2, evidence: '   ' }, unfixed, 1],
    // A referenced fix retracts, and its reason has to name the reference.
    [
      [layer('a', 'PAYLOAD_REACHES_SINK')],
      checked,
      inScope,
      { fixed: 'YES', complete: true, reference: '#412', searched: 'git log', evidence: '' },
      1,
    ],
  ]
  const seen = new Set()
  for (const args of cases) {
    const r = decideGate(...args)
    assert.notEqual(r.status, 'PROCEED')
    assert.ok(r.reason && r.reason.trim(), `${r.status} came back with no reason`)
    seen.add(r.status)
  }
  // The zero guard for the fix above. Ten rows all returning BLOCKED is what a
  // silently-broken argument list looks like, and it is indistinguishable from
  // coverage unless the spread of statuses is checked.
  for (const status of ['BLOCKED', 'NOT_EXPLOITABLE', 'NEEDS_MORE_INFO', 'OUT_OF_SCOPE', 'NOT_VULNERABLE', 'ALREADY_FIXED']) {
    assert.ok(seen.has(status), `no row reached ${status}, so its reason is ungraded`)
  }
})

// ------------------------------------------------- checkpoint 2.4b

// "If Integration or External ... the required external precondition is stated
// explicitly" is a pass criterion the JSON Schema cannot express, since it is
// conditional on another field. Unenforced, an integration finding reaches
// Phase 4 without the precondition that makes it exploitable ever being named.

test('an internal root cause needs no external precondition', () => {
  assert.equal(missingPrecondition({ rootCause: 'internal' }), false)
  // `Internal` is the same claim, and it used to be told to state the external
  // precondition of a trigger it had just placed inside the repository. The cap
  // read it the other way, which is the disagreement the shared predicate ends.
  assert.equal(missingPrecondition({ rootCause: 'Internal' }), false, 'the same claim, differently cased')
})

// The demanding side, widened past the two enum members: `required` is the only
// thing the runtime validator enforces, so a root cause nothing in the schema
// stops is a root cause this gate has to price.
test('anything but internal without a precondition is caught', () => {
  for (const rootCause of ['integration', 'external', 'third-party', '']) {
    assert.equal(missingPrecondition({ rootCause }), true, `${rootCause} must require one`)
    assert.equal(
      missingPrecondition({ rootCause, externalPrecondition: '   ' }),
      true,
      'whitespace is not a stated precondition',
    )
    assert.equal(
      missingPrecondition({ rootCause, externalPrecondition: 'the upstream API returns a negative length' }),
      false,
    )
  }
})

test('a dead impact agent does not throw the precondition check', () => {
  for (const dead of [null, undefined]) {
    assert.equal(missingPrecondition(dead), false, 'the VERIFIED gate handles a dead agent first')
  }
})
