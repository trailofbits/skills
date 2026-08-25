import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const REVIEW = script('triage-poc.js')
const confidenceBand = loadFn(REVIEW, 'confidenceBand')
const tallyChallenges = loadFn(REVIEW, 'tallyChallenges')
// `namedLevels` alongside both of these: they call it, and `loadFn` evaluates one
// function alone, where a call to a sibling is a ReferenceError.
const { severityCapViolation, reportProblem, namedLevels } = loadFns(
  REVIEW,
  'severityCapViolation',
  'reportProblem',
  'namedLevels',
  'externalRootCause',
)
const { alreadyFixedStands, citedReference } = loadFns(REVIEW, 'alreadyFixedStands', 'citedReference')
const artifactProblem = loadFn(REVIEW, 'artifactProblem')
const settledByStageOne = loadFn(REVIEW, 'settledByStageOne')

const REVIEW_SRC = readFileSync(REVIEW, 'utf8')
const SKILL_MD = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'skills', 'fp-check', 'SKILL.md'),
  'utf8',
)

const KEYS = ['reachable', 'recoverable', 'by-design', 'already-fixed', 'real-deployment']
const won = (key) => ({ key, winner: 'REBUTTAL', challenge: `c:${key}` })
const lost = (key) => ({ key, winner: 'CHALLENGE', challenge: `c:${key}` })

// ---------------------------------------------------------------- bands

test('bands follow checkpoints.md 5.1 exactly', () => {
  assert.equal(confidenceBand(5).label, 'HIGH')
  assert.equal(confidenceBand(4).label, 'MEDIUM')
  assert.equal(confidenceBand(3).label, 'MEDIUM')
  assert.equal(confidenceBand(2).label, 'LOW')
  assert.equal(confidenceBand(1).label, 'LOW')
  assert.equal(confidenceBand(0).label, 'NONE')
})

test('only HIGH and MEDIUM proceed', () => {
  assert.equal(confidenceBand(5).action, 'PROCEED')
  assert.equal(confidenceBand(3).action, 'PROCEED_WITH_UNCERTAINTIES')
  assert.equal(confidenceBand(2).action, 'DO_NOT_SUBMIT')
  assert.equal(confidenceBand(0).action, 'DO_NOT_SUBMIT')
})

// ------------------------------------------------------------- tallying
//
// The concept-prover analogue of "dedup against SEEN, not CONFIRMED": the tally
// must run against the EXPECTED challenge list, not against whatever came back.
// Counting the returned array instead lets a dead agent shrink the denominator
// and silently raise confidence, which is the same class of bug — a result
// disappearing from the accounting rather than counting against the finding.

test('all five defeated gives HIGH', () => {
  const t = tallyChallenges(KEYS.map(won), KEYS)
  assert.equal(t.defeated, 5)
  assert.equal(t.unrebutted.length, 0)
  assert.equal(confidenceBand(t.defeated).label, 'HIGH')
})

test('a dead agent counts AGAINST the finding, it does not vanish', () => {
  // Four challenges returned, all rebutted. The fifth agent died.
  const returned = KEYS.slice(0, 4).map(won)
  const t = tallyChallenges(returned, KEYS)
  assert.equal(t.defeated, 4, 'the missing challenge must not count as defeated')
  assert.equal(t.missing, 1)
  assert.equal(confidenceBand(t.defeated).label, 'MEDIUM')
  assert.ok(
    t.unrebutted.some((u) => u.key === 'real-deployment'),
    'the unanswered challenge must appear as unrebutted',
  )
})

test('all agents dying yields NONE, never HIGH', () => {
  const t = tallyChallenges([], KEYS)
  assert.equal(t.defeated, 0)
  assert.equal(t.missing, 5)
  assert.equal(confidenceBand(t.defeated).action, 'DO_NOT_SUBMIT')
})

test('nulls from dead agents are filtered, not counted or thrown on', () => {
  const t = tallyChallenges([won('reachable'), null, undefined, won('by-design')], KEYS)
  assert.equal(t.defeated, 2)
  assert.equal(t.unrebutted.length, 3)
})

test('a duplicate key cannot inflate the defeated count', () => {
  const t = tallyChallenges([won('reachable'), won('reachable'), won('reachable')], KEYS)
  assert.equal(t.defeated, 1, 'tally is over expected keys, so duplicates collapse')
})

test('an unknown key is ignored rather than counted', () => {
  const t = tallyChallenges([won('not-a-real-challenge')], KEYS)
  assert.equal(t.defeated, 0)
})

test('a lost challenge is reported with its argument text', () => {
  const others = KEYS.filter((k) => k !== 'recoverable').map(won)
  const t = tallyChallenges([lost('recoverable'), ...others], KEYS)
  assert.equal(t.defeated, 4)
  assert.equal(t.unrebutted.length, 1)
  assert.equal(t.unrebutted[0].key, 'recoverable')
  assert.equal(t.unrebutted[0].challenge, 'c:recoverable')
  assert.equal(confidenceBand(t.defeated).action, 'PROCEED_WITH_UNCERTAINTIES')
})

test('a missing challenge is labelled as having no verdict', () => {
  const t = tallyChallenges([], ['reachable'])
  assert.equal(t.unrebutted[0].challenge, 'no verdict returned')
})

// The only thing that told a reviewer who ARGUED apart from an agent that never
// ran was `unrebutted[].challenge`, a sentinel string nothing was told to read —
// and the band branch reported both with the same reason, the one SKILL.md maps
// to FALSE POSITIVE.
test('an unanswered challenge is marked as such, not merged with one that was argued', () => {
  const t = tallyChallenges([lost('reachable')], ['reachable', 'recoverable'])
  assert.equal(t.unrebutted.length, 2)
  assert.equal(t.unrebutted.find((u) => u.key === 'reachable').answered, true)
  assert.equal(t.unrebutted.find((u) => u.key === 'recoverable').answered, false)
  assert.equal(t.defeated, 0, 'silence still costs the band, exactly as before')
})

// `missing` was `expectedKeys.length - byKey.size`, so a verdict filed under an
// unknown key — ignored everywhere else here — deflated it and the log undercounted
// the agents that died.
test('missing counts expected challenges nobody answered, not returned verdicts', () => {
  const t = tallyChallenges([won('not-a-real-challenge')], KEYS)
  assert.equal(t.missing, 5, 'an unknown key answers none of the five')
  assert.equal(t.defeated, 0)
})

test('empty expected list returns cleanly rather than throwing', () => {
  const t = tallyChallenges([], [])
  assert.equal(t.defeated, 0)
  assert.equal(t.unrebutted.length, 0)
})

test('undefined verdicts array returns cleanly rather than throwing', () => {
  const t = tallyChallenges(undefined, KEYS)
  assert.equal(t.defeated, 0)
  assert.equal(t.unrebutted.length, 5)
})

// --------------------------------------- challenge 4 overrides the band, if cited

// checkpoints.md 5.1: "a fix exists -> the band does not get a vote". The script
// reads WHETHER the challenge stands off the unrebutted list rather than off the
// returned verdicts, so a dead challenge-4 agent cannot escape it — and then reads
// the CITATION off the verdict, because a retraction has to point at something.
// triage-static refuses `fixed: YES` with no reference for that reason and this is
// the same rule one stage later: an unreferenced retraction is the failure mode
// that silently discards a real finding, and here the finding it discarded had
// been built, executed and linted. A missing verdict still counts against the
// finding — `tallyChallenges` lowers the band by it either way.

test('a DEAD already-fixed agent also appears in the unrebutted list', () => {
  // The gap this closes: `verdicts.find(v => v.key === 'already-fixed' && ...)`
  // matched nothing when the agent died, so the unconditional rule was skipped
  // while every other challenge counted a missing verdict against the finding.
  const returned = KEYS.filter((k) => k !== 'already-fixed').map(won)
  const t = tallyChallenges(returned, KEYS)
  assert.equal(t.defeated, 4)
  assert.ok(
    t.unrebutted.some((u) => u.key === 'already-fixed'),
    'a missing verdict counts as won by the challenge, challenge 4 included',
  )
})

test('a lost challenge 4 retracts on the citation it gave', () => {
  const others = KEYS.filter((k) => k !== 'already-fixed').map(won)
  const cited = { ...lost('already-fixed'), reference: '99a4704 (#412)', complete: true, evidence: 'the digest moved up a layer' }
  const returned = [cited, ...others]
  const t = tallyChallenges(returned, KEYS)
  assert.equal(alreadyFixedStands(t.unrebutted, returned), '99a4704 (#412)')
})

// The direction that matters. An agent that died searched nothing, and an agent
// that awarded the challenge with a blank `reference` cited nothing; neither is a
// fix, and returning ALREADY_FIXED on either told the user a bug was "already
// fixed by <nothing>" and threw away a PoC that had run.
//
// The `evidence`-only case is the third: `evidence` is required of ALL FIVE
// challenges, so reading the citation out of it made the check unfalsifiable —
// any argued win retracted, "the sink was rewritten during a later refactor"
// included. `reference` is the field that holds a commit, PR, issue or advisory
// ID and nothing else, exactly as HISTORY_SCHEMA's does one stage earlier.
test('an uncited or dead challenge 4 does not retract', () => {
  const others = KEYS.filter((k) => k !== 'already-fixed').map(won)
  // `complete: true` throughout, so that what each case tests is the CITATION and
  // not the completeness gate one line above it.
  const whole = { ...lost('already-fixed'), complete: true }
  const uncited = [
    others,
    [whole, ...others],
    [{ ...whole, reference: '  ' }, ...others],
    [{ ...whole, evidence: 'the sink was rewritten during a later refactor' }, ...others],
    // A non-blank check on `reference` passed a word standing in for a citation,
    // and SKILL.md then printed "RETRACTED — already fixed by n/a".
    [{ ...whole, reference: 'n/a' }, ...others],
    [{ ...whole, reference: 'unknown commit' }, ...others],
    [{ ...whole, reference: 'see evidence' }, ...others],
    // "Carries a digit" was the replacement for "non-blank", and these two pass
    // it while citing nothing lookupable.
    [{ ...whole, reference: 'see evidence at auth.py:31' }, ...others],
    [{ ...whole, reference: 'fixed sometime in the 2.x line' }, ...others],
    // A bare integer is a line number as often as it is a PR, and admitting one
    // makes "fixed in 2021" a citation. The keyword form (`PR 4521`) carries the
    // context that tells them apart and is accepted above; this is not.
    [{ ...whole, reference: '4521' }, ...others],
    [{ ...whole, reference: 'fixed in 2021.03' }, ...others],
    // A hyphenated token carrying a digit is not an advisory ID, and a version
    // inside a FILENAME is not a version citation — challenge 4's own prompt
    // names a bare file:line as a non-citation, and `auth-v2.go:118` is one.
    [{ ...whole, reference: 'fixed in a post-2020 refactor' }, ...others],
    [{ ...whole, reference: 'a follow-up commit, not-found-1' }, ...others],
    [{ ...whole, reference: 'internal-fix-2' }, ...others],
    [{ ...whole, reference: 'src/handlers/auth-v2.go:118' }, ...others],
  ]
  for (const returned of uncited) {
    const t = tallyChallenges(returned, KEYS)
    assert.equal(alreadyFixedStands(t.unrebutted, returned), null)
    // and it is still counted against the finding, by the band
    assert.equal(t.defeated, 4)
    assert.equal(confidenceBand(t.defeated).label, 'MEDIUM')
  }
})

// checkpoints.md 5.1: "an incomplete or partial fix is reported as such". Stage 1
// has gated on `complete` since it was written; Stage 3 retracted on ANY cited
// award, so a fix that closed one of two sinks discarded a demonstrated,
// still-live bug and wrote no report. The challenge still costs a band step.
test('a cited PARTIAL fix is not a retraction', () => {
  const others = KEYS.filter((k) => k !== 'already-fixed').map(won)
  for (const complete of [false, undefined, null, 'yes', 1]) {
    const partial = { ...lost('already-fixed'), reference: '99a4704', complete }
    const returned = [partial, ...others]
    const t = tallyChallenges(returned, KEYS)
    assert.equal(alreadyFixedStands(t.unrebutted, returned), null, `complete ${JSON.stringify(complete)}`)
    assert.equal(t.defeated, 4)
  }
})

// The shapes a citation honestly takes. A short sha is often all letters, so a
// digit test refused `deadbeef` — reporting, terminally, a bug that was fixed.
//
// The second row is the wrapper, and each one was rejected while the test split
// on whitespace and anchored every token: `owner/repo#N` is the canonical
// cross-repo reference and exactly the integration case this search exists for,
// and a backticked sha, a markdown link and an angle-bracketed URL are how a model
// writes one in prose. Rejecting them is not harmless — Stage 1 then writes a note
// saying no reference was given and reports an already-fixed bug as live.
test('every honest citation shape retracts', () => {
  const others = KEYS.filter((k) => k !== 'already-fixed').map(won)
  for (const reference of [
    'deadbeef', 'abcfeed', '#412', 'CVE-2024-1234', 'GHSA-jf85-cpcp-j695', 'v2.3.1', 'https://github.com/o/r/pull/412',
    // Real GHSA IDs whose LAST segment is all letters. The rule required it to
    // end in a digit, and GHSA's alphabet is `23456789cfghjmpqrvwx`, so about one
    // real ID in twenty was rejected — turning a correctly cited retraction into
    // NEEDS_MORE_INFO here and a live-bug report one stage earlier. The third
    // carries no digit in its FIRST segment either.
    'GHSA-c2qf-rxjj-qqgw', 'GHSA-4hjh-wcwx-xvwj', 'GHSA-jchw-25xp-jwwc', 'RUSTSEC-2021-0093', 'GO-2022-0603',
    // GitHub shorthand. `/` was not in the separator class, so the same reference
    // was a citation inside a full URL and not a citation on its own.
    'pull/882', 'issues/1234',
    'openssl/openssl#12345', 'torvalds/linux@a1b2c3d', 'PR 4521', 'issue 1234', 'v3', '`a1b2c3d`',
    '[the fix](https://github.com/o/r/pull/412)', '<https://github.com/o/r/commit/a1b2c3d>',
  ]) {
    const returned = [{ ...lost('already-fixed'), reference, complete: true }, ...others]
    const t = tallyChallenges(returned, KEYS)
    assert.equal(alreadyFixedStands(t.unrebutted, returned), reference)
  }
})

test('a rebutted already-fixed challenge does not trigger the rule', () => {
  const returned = KEYS.map(won)
  const t = tallyChallenges(returned, KEYS)
  assert.equal(alreadyFixedStands(t.unrebutted, returned), null)
})

test('the rule survives an empty or absent list', () => {
  for (const input of [[], undefined, null, [null, undefined]]) {
    assert.equal(alreadyFixedStands(input, input), null)
  }
})

test('the rule keys on already-fixed and not on any other lost challenge', () => {
  const returned = [{ ...lost('recoverable'), evidence: 'the panic is recovered' }]
  const t = tallyChallenges(returned, ['recoverable'])
  assert.equal(alreadyFixedStands(t.unrebutted, returned), null)
})

// ------------------------------------------------------------ severity caps

// checkpoints.md 2.4b caps an integration or external root cause at Medium, and
// 2.5 puts a hardening gap at "medium priority, defense-in-depth". The report
// prompt says so, but a prompt is not an enforcement mechanism — what comes back
// is whatever severity the agent chose.

test('an internal vulnerability may carry any severity', () => {
  for (const s of ['Critical', 'High', 'Medium', 'Low', 'Informational']) {
    assert.equal(severityCapViolation(s, 'internal', 'vulnerability'), null, `${s} is allowed`)
  }
})

test('integration and external root causes are capped at Medium', () => {
  for (const rootCause of ['integration', 'external']) {
    for (const s of ['Critical', 'High']) {
      const v = severityCapViolation(s, rootCause, 'vulnerability')
      assert.ok(v, `${s} on a ${rootCause} root cause must be caught`)
      assert.match(v, /2\.4b/)
      assert.match(v, new RegExp(s), 'the message must name the severity it rejected')
    }
    for (const s of [
      'Medium',
      'Low',
      'Informational',
      // A below-cap rating whose prose mentions no other level. A bare substring
      // test blocked the report over a violation it had not committed, which at
      // this stage turns a five-challenge-defeated PoC into NEEDS MORE INFO; and
      // matching the leftmost level name with an unbounded indexOf hit 'high'
      // inside "Highly" and did the same.
      'Low — highly situational',
      'Highly situational, ultimately Low',
    ]) {
      assert.equal(severityCapViolation(s, rootCause, 'vulnerability'), null, s)
    }
  }
})

// The direction the leftmost reading opened in exchange: an above-cap rating
// ESCAPED whenever a lower level name appeared earlier in the string. `low`
// inside "Allowlist" beat the "High" the agent actually wrote, so
// severityCapViolation returned null and the report shipped uncapped — which is
// the mechanism the measured head-to-head credits 3/3 against 0/3, defeated by a
// stray word.
test('an above-cap rating cannot escape by naming a lower level first', () => {
  for (const s of ['Allowlist bypass — High', 'Critical (RCE)', 'CRITICAL', 'critical', 'High']) {
    const v = severityCapViolation(s, 'integration', 'vulnerability')
    assert.ok(v, `${s} must be caught`)
    assert.match(v, /2\.4b/)
  }
})

// And the rows no positional rule ever got right. Reading the HIGHEST level
// named blocked `Low (the affected path is not business-critical)` on a violation
// it had not committed; restricting that to where the cap LOWERS then let
// `Critical (affects low-privilege users)` and `High (was Informational before
// the PoC)` ship uncorrected, because each names a level below the cap and the
// restriction read that as "do not touch". Both directions lose: one discards a
// defeated PoC, the other reports an inflated number. Neither is chosen — the
// rating is refused as unreadable and the author is asked which one it is.
test('a rating naming two levels is refused, in either direction', () => {
  for (const s of [
    'Critical (affects low-privilege users)',
    'Low (the affected path is not business-critical)',
    'Medium/High',
    'Medium-High',
    'High/Critical',
    'High (was Informational before the PoC)',
    'Critical — a low-level memory corruption in the parser',
    'High — the low-entropy nonce is predictable',
    'Critical: full RCE. Not Low.',
    'Informational (no high-value data)',
    'Critically low impact — Informational',
  ]) {
    for (const rootCause of ['integration', 'external', 'internal']) {
      const v = severityCapViolation(s, rootCause, 'vulnerability')
      assert.ok(v, `${s} on a ${rootCause} root cause must not be silently passed`)
      assert.match(v, /names \d+ levels/, s)
      assert.match(v, /exactly one/, 'the message has to name the fix')
    }
    // and the gate the report actually meets first says the same thing
    const problem = reportProblem({ ...goodReport, severity: s })
    assert.ok(problem, `${s} must not reach REPORTED`)
    assert.match(problem, /state exactly one/)
  }
})

// Round 7 trimmed a blank severity and stopped there. `Unknown` names no level,
// so the cap read it as below the cap and returned null — and it shipped as the
// REPORTED severity, which SKILL.md tells the orchestrator IS the finding's
// rating, with no cap applied. Stage 2 falls back to Stage 1's number for this
// shape; this stage has nothing to fall back to, so it has to refuse.
test('a severity naming no level at all cannot ship as the report rating', () => {
  for (const severity of ['Unknown', 'unknown', 'n/a', 'TBD', 'see rationale', 'P1']) {
    const problem = reportProblem({ ...goodReport, severity })
    assert.ok(problem, `severity ${JSON.stringify(severity)} must block`)
    assert.match(problem, /names none of Critical, High, Medium, Low or Informational/)
  }
})

test('the five enum members reach REPORTED', () => {
  for (const severity of ['Critical', 'High', 'Medium', 'Low', 'Informational']) {
    assert.equal(reportProblem({ ...goodReport, severity }), null, severity)
  }
})

test('namedLevels reports every distinct level, word-bounded, most severe first', () => {
  assert.deepEqual(namedLevels('Medium/High'), ['high', 'medium'])
  assert.deepEqual(namedLevels('Allowlist bypass — High'), ['high'])
  assert.deepEqual(namedLevels('Highly situational, ultimately Low'), ['low'])
  assert.deepEqual(namedLevels('Unknown'), [])
})

test('a hardening gap is capped at Medium even with an internal root cause', () => {
  const v = severityCapViolation('High', 'internal', 'hardening_gap')
  assert.ok(v)
  assert.match(v, /2\.5/)
  assert.equal(severityCapViolation('Medium', 'internal', 'hardening_gap'), null)
})

test('the root-cause cap is reported ahead of the classification cap', () => {
  // Both apply; the message names the root cause, which is the stronger reason
  // and the one that drives remediation.
  const v = severityCapViolation('Critical', 'integration', 'hardening_gap')
  assert.match(v, /integration/)
})

test('an unrecognised severity is not silently treated as below the cap', () => {
  // Returning null read as "no violation", which is a gate whose whole job is to
  // bound a number answering for a string it could not read. `reportProblem`
  // refuses these first and with a better message, so this is what the function
  // says when it is called and graded on its own.
  for (const severity of [undefined, '', 'Sev-1', 'P0']) {
    const v = severityCapViolation(severity, 'integration', 'vulnerability')
    assert.ok(v, `severity ${JSON.stringify(severity)} must not read as below the cap`)
    assert.match(v, /no cap can be checked against it/)
  }
})


// ------------------------------------------------- checkpoint 4.3, re-checked

// build-poc gates on `built`, `executed` and `lintPassed` — three booleans the
// builder fills in itself, in a script with no Bash to verify them. SKILL.md
// nonetheless says placeholders are "enforced by poc-lint.sh, not by good
// intentions". This is what makes that true: an independent agent re-runs the
// linter against poc.absolutePath and this decides what its answer means.

const cleanCheck = {
  fileExists: true,
  lintExitZero: true,
  reimplementation: 'NOT_DEFINED',
  reRun: 'REPRODUCED',
  reRunNotes: '',
  evidence: 'ran it',
}

test('a clean artifact check does not block', () => {
  assert.equal(artifactProblem(cleanCheck), null)
})

// Principle 5, and the only code that decides it. poc-lint.sh's
// `possible-reimplementation` is a NOTE that exits 0 — a grep cannot tell a
// façade re-export or a pytest fixture from a copy, and made fatal it returned
// BUILD_FAILED on all three. Demoted with the question routed nowhere, a PoC that
// pasted the vulnerable function in passed the note AND the symbol rule, because
// the copy's own definition supplies the mention, and came back REPORTED. The
// reviewer opens both files; this reads the answer.
test('a PoC that copies the code under test blocks', () => {
  const problem = artifactProblem({ ...cleanCheck, reimplementation: 'COPY_OF_TARGET', evidence: 'parser.py:47 pasted in' })
  assert.ok(problem)
  assert.match(problem, /reimplements the code under test/)
  assert.match(problem, /parser\.py:47/, 'the reviewer evidence belongs in the reason')
})

test('a local driver sharing the name does not block', () => {
  assert.equal(artifactProblem({ ...cleanCheck, reimplementation: 'LOCAL_DRIVER', evidence: 'poc.py:12 vs parser.py:47' }), null)
})

// `evidence` was read only inside the COPY_OF_TARGET branch, so the two answers
// that CLEAR Principle 5 cleared it on nothing: `required` checks presence, not
// content, so `evidence: ''` validates. Both are judgements about two bodies —
// NOT_DEFINED means no copy under ANY name — so the one check that decides
// Principle 5 became a self-report, which is what every other gate here refuses.
test('a Principle 5 clearance with no evidence does not clear', () => {
  for (const reimplementation of ['NOT_DEFINED', 'LOCAL_DRIVER']) {
    for (const evidence of [undefined, '', '   ', '\n\t']) {
      const problem = artifactProblem({ ...cleanCheck, reimplementation, evidence })
      assert.ok(problem, `${reimplementation} / ${JSON.stringify(evidence)} must not clear`)
      assert.match(problem, /what it compared/)
    }
  }
})

// The enum's own `description` is what the runtime validator puts in front of the
// model, and it carried the same defect the prompt did: "it does not define the
// symbol" is literally TRUE of a copy pasted under a DIFFERENT name, so the two
// clearing answers were not exclusive of the one case the linter cannot see —
// rule 6 keys on the leaf and prints no note, rule 8 is satisfied by a mention in
// a comment. Described by logic, the builder prompt's "renaming past the note
// buys nothing" is true; described by name, it is false.
test('ARTIFACT_SCHEMA puts the reimplementation question in terms of logic, not name', () => {
  const block = REVIEW_SRC.match(/reimplementation: \{[\s\S]*?\n {4}\},/)
  assert.ok(block, 'ARTIFACT_SCHEMA.reimplementation not found; this pin is stale')
  assert.match(block[0], /under ANY name/, 'NOT_DEFINED must not be satisfiable by a rename')
  assert.match(block[0], /whatever it was renamed to/, 'COPY_OF_TARGET must claim the renamed case')
})

// Affirmatively graded, for the reason every other gate here is: the enum is
// advisory and `required` is all the runtime validator enforces, so an omitted
// or misspelt answer must not read as a clearance.
test('an omitted or unrecognised reimplementation verdict is not a clearance', () => {
  for (const value of [undefined, '', 'none', 'NO', 'not_defined']) {
    const check = { ...cleanCheck, reimplementation: value }
    assert.ok(artifactProblem(check), `${JSON.stringify(value)} must not clear Principle 5`)
  }
})

test('a dead artifact agent blocks: 4.3 unverified is not 4.3 passed', () => {
  for (const dead of [null, undefined]) {
    const problem = artifactProblem(dead)
    assert.ok(problem, 'a missing answer must not read as a passing one')
    assert.match(problem, /returned nothing/)
  }
})

test('a missing PoC file blocks', () => {
  const problem = artifactProblem({ ...cleanCheck, fileExists: false })
  assert.ok(problem)
  assert.match(problem, /no PoC file/)
})

test('a lint failure blocks even though the builder reported lintPassed', () => {
  // The whole point: the builder said it passed, the reviewer ran it and it
  // did not. The reviewer wins.
  const problem = artifactProblem({ ...cleanCheck, lintExitZero: false, lintOutput: 'stub-body' })
  assert.ok(problem)
  assert.match(problem, /did not exit 0/)
  assert.match(problem, /stub-body/, 'the linter output belongs in the reason')
})

test('a lint failure with no captured output still reports a reason', () => {
  const problem = artifactProblem({ fileExists: true, lintExitZero: false })
  assert.match(problem, /no output captured/)
})

// `reRunSucceeded` was one boolean over two opposite results, and the gate that
// ought to have read it read neither: nothing in code required the PoC to
// reproduce for the one reader who did not build it, so a reviewer's "ran it; the
// balance is unchanged" came back REPORTED at High. Four assertions replace the
// one that stood here, because the input it was written for is only half of what
// `false` used to mean.
test('a PoC the reviewer ran that did not reproduce blocks', () => {
  const problem = artifactProblem({ ...cleanCheck, reRun: 'DID_NOT_REPRODUCE', reRunNotes: 'the balance is unchanged' })
  assert.ok(problem)
  assert.match(problem, /did not reproduce the impact/)
  assert.match(problem, /the balance is unchanged/, "the reviewer's notes belong in the reason, as lintOutput does")
})

test('a PoC that could not be run here does NOT block', () => {
  // A testnet or service-dependent PoC can legitimately fail to reproduce on
  // the reviewer's machine. That is a boundary for the report's "unproven"
  // section, not evidence the finding is wrong — and this is the direction that
  // must not regress into a false dismissal.
  assert.equal(artifactProblem({ ...cleanCheck, reRun: 'COULD_NOT_RUN_HERE', reRunNotes: 'no ES cluster here' }), null)
})

// The clearing answer owes its reason, exactly as the Principle 5 clearance above
// does: "could not run here" with nothing behind it is the same self-report as an
// evidence-free clearance, and it is the answer that BUYS the pass.
test('an environmental boundary with no reason given does not clear', () => {
  for (const reRunNotes of [undefined, '', '   ', '\n\t']) {
    const problem = artifactProblem({ ...cleanCheck, reRun: 'COULD_NOT_RUN_HERE', reRunNotes })
    assert.ok(problem, `${JSON.stringify(reRunNotes)} must not clear`)
    assert.match(problem, /did not say what stopped it/)
  }
})

test('an omitted or unrecognised re-run answer is not a reproduction', () => {
  for (const reRun of [undefined, '', 'true', 'reproduced', 'YES', 'PARTIAL']) {
    const problem = artifactProblem({ ...cleanCheck, reRun })
    assert.ok(problem, `${JSON.stringify(reRun)} must not read as a reproduction`)
    assert.match(problem, /no usable answer/)
  }
})

test('file existence is checked before lint, so the reason is the useful one', () => {
  const problem = artifactProblem({ fileExists: false, lintExitZero: false })
  assert.match(problem, /no PoC file/, 'a missing file explains the lint failure')
})

// ------------------------------------------------------- checkpoint 6.1
//
// REPORT_SCHEMA requires all four fields, and JSON Schema `required` checks
// presence and not content: `unproven: ''` and `reportPath: ''` both validate.
// `unproven` was gated with .trim(); `reportPath` was not gated at all, despite
// the prompt saying "reportPath must be a file you actually wrote, not a path
// you intend to use" — a prompt is a request the model may decline. An empty one
// returned REPORTED with no report to point at, and reached the severity-cap
// block message as "The report at  carries a severity...".

const goodReport = {
  severity: 'High',
  severityRationale: 'internal root cause, unauthenticated',
  reportPath: '/tmp/wf-worktree-3/finding-negative-transfer.md',
  unproven: 'no network route was exercised',
}

test('a complete report does not block', () => {
  assert.equal(reportProblem(goodReport), null)
})

test('a dead report agent blocks: 6.1 unverified is not 6.1 passed', () => {
  for (const dead of [null, undefined]) {
    const problem = reportProblem(dead)
    assert.ok(problem, 'a missing answer must not read as a passing one')
    assert.match(problem, /returned nothing/)
  }
})

test('an empty or whitespace unproven blocks — every PoC has a boundary', () => {
  for (const unproven of [undefined, '', '   ', '\n\t']) {
    const problem = reportProblem({ ...goodReport, unproven })
    assert.ok(problem, `unproven ${JSON.stringify(unproven)} must block`)
    assert.match(problem, /unproven/)
  }
})

test('an empty or whitespace reportPath blocks, and the reason names the field', () => {
  for (const reportPath of [undefined, '', '   ', '\n']) {
    const problem = reportProblem({ ...goodReport, reportPath })
    assert.ok(problem, `reportPath ${JSON.stringify(reportPath)} must block`)
    assert.match(problem, /reportPath/)
    assert.ok(problem.trim(), 'a halt must explain itself')
  }
})

// The number the finding ships with. SKILL.md tells the orchestrator the
// top-level `severity` IS the rating, so a blank shipped REPORTED with no rating
// at all. Stage 2 has a fallback for this shape (`unknownSeverity` ->
// `verification.severity`); Stage 3 has none, so it refuses — at this gate, which
// names the fix, and the cap behind it refuses too rather than reading a string it
// could not parse as below itself.
test('an empty or whitespace severity blocks — REPORTED cannot ship without a rating', () => {
  for (const severity of [undefined, '', '   ', '\n\t']) {
    const problem = reportProblem({ ...goodReport, severity })
    assert.ok(problem, `severity ${JSON.stringify(severity)} must block`)
    assert.match(problem, /severity/)
    // and this gate is the one that names the fix; the cap behind it refuses too
    assert.match(
      severityCapViolation(severity, 'integration', 'vulnerability'),
      /no cap can be checked against it/,
      'a blank must not read as below the cap',
    )
  }
})

test('unproven is reported ahead of reportPath when both are blank', () => {
  // Ordering is not arbitrary: a report agent that filled in neither has not
  // written a report at all, and "what remains unproven" is the checkpoint the
  // Completion Gate lists.
  const problem = reportProblem({ ...goodReport, unproven: '', reportPath: '' })
  assert.match(problem, /unproven/)
})

// `confidenceBand` hardcoded `defeated === 5` for HIGH while every other consumer
// used CHALLENGES.length. Correct today and silently wrong the moment a sixth
// challenge is added: HIGH becomes unreachable and every perfect review reports
// MEDIUM. `total` is a defaulted parameter rather than a reference to the const,
// because the tests evaluate this function alone where a free variable throws.
test('the band scales with the challenge count instead of hardcoding it', () => {
  assert.equal(confidenceBand(5, 5).label, 'HIGH')
  assert.equal(confidenceBand(6, 6).label, 'HIGH', 'a sixth challenge must not make HIGH unreachable')
  assert.equal(confidenceBand(5, 6).label, 'MEDIUM', 'and one lost is no longer HIGH')
  assert.equal(confidenceBand(5).label, 'HIGH', 'the default still matches todays five')
})

// ------------------------------------- Stage 1 settled it: no exploit is owed
//
// The measured failure this covers is not a code bug. Stage 3 refused correctly;
// the orchestrator, still holding a user request for a PoC, then built the
// exploit by hand and its final answer hedged — reproducing, verbatim, the
// sentence the no-plugin baseline arm produces on the same case. Refusal has no
// degraded mode, so when the user has asked for a PoC the model sides with the
// user and reverts to unguarded behaviour wholesale.
//
// Nothing below relaxes the gate. The exploit is refused exactly as before; what
// changed is that the refusal now reads as an ANSWER ABOUT THE FINDING rather
// than as a complaint about the caller's arguments, and it names the deliverable
// that replaces the PoC.

const SETTLED = [
  'FALSE_POSITIVE',
  'NOT_EXPLOITABLE',
  'NOT_VULNERABLE',
  'ALREADY_FIXED',
  'OUT_OF_SCOPE',
]

// Read out of the script rather than trusted: this list is the join between the
// gate and the reporting table in SKILL.md, and a status added to one of the
// three without the other two is exactly the drift that produces a verdict with
// no documented way to say it.
test('the settled list these tests grade is the list the script branches on', () => {
  const literal = /const settled = \[([\s\S]*?)\]/.exec(REVIEW_SRC)
  assert.ok(literal, 'settledByStageOne no longer declares a `settled` array; this section is stale')
  const inScript = [...literal[1].matchAll(/'([A-Z_]+)'/g)].map((m) => m[1])
  assert.ok(inScript.length > 0, 'the array literal is empty; this test is grading nothing')
  assert.deepEqual(new Set(inScript), new Set(SETTLED))
})

test('every terminal Stage 1 verdict is recognised as settled, with its reason', () => {
  for (const status of SETTLED) {
    const s = settledByStageOne({ verification: { status, reason: 'blocked at the allowlist' } })
    assert.ok(s, `${status} is a verdict and must be recognised as one`)
    assert.equal(s.status, status)
    assert.equal(s.reason, 'blocked at the allowlist')
  }
})

test('TRUE_POSITIVE is not settled — it is the one status that builds', () => {
  assert.equal(settledByStageOne({ verification: { status: 'TRUE_POSITIVE' } }), null)
})

// The distinction the whole section rests on. NEEDS_MORE_INFO is a fact still to
// establish and BLOCKED is an analysis that could not run; neither is an answer,
// and SKILL.md's own history records that rounding either to FALSE POSITIVE
// killed a real finding. They must keep the arg gate's "go back and fix it"
// message rather than acquiring a reporting template.
test('NEEDS_MORE_INFO and BLOCKED are not settled: they are re-run, not reported', () => {
  for (const status of ['NEEDS_MORE_INFO', 'BLOCKED']) {
    assert.equal(
      settledByStageOne({ verification: { status } }),
      null,
      `${status} is not a verdict and must not be reportable as one`,
    )
  }
})

test('an unrecognised status falls through to the arg gate rather than settling', () => {
  for (const status of ['', 'PROCEED', 'REPORTED', 'not_exploitable', 'TRIAGED', 'anything']) {
    assert.equal(
      settledByStageOne({ verification: { status } }),
      null,
      `${JSON.stringify(status)} must not be treated as a verdict`,
    )
  }
})

test('a surrounding-whitespace status is still the verdict it names', () => {
  const s = settledByStageOne({ verification: { status: '  ALREADY_FIXED\n' } })
  assert.ok(s)
  assert.equal(s.status, 'ALREADY_FIXED', 'the trimmed name is what SKILL.md is keyed on')
})

test('an absent verification neither throws nor settles', () => {
  for (const a of [undefined, null, {}, { verification: null }, { verification: {} }, 'nonsense']) {
    assert.equal(settledByStageOne(a), null)
  }
})

// Trimmed for the reason every other relayed string in this script is trimmed:
// `reason: '   '` is truthy and would reach the orchestrator as a verdict that
// explains itself with blank space.
test('a whitespace reason becomes empty rather than being relayed as one', () => {
  for (const reason of [undefined, '', '   ', '\n\t']) {
    assert.equal(settledByStageOne({ verification: { status: 'FALSE_POSITIVE', reason } }).reason, '')
  }
})

// ------------------------------------------------- the same gate, wired up

const SETTLED_ARGS = {
  baseDir: '/plugin/skills/fp-check',
  finding: { summary: '`==` on session tokens is a timing oracle', sink: 'session.py:88' },
  verification: {
    status: 'ALREADY_FIXED',
    reason: 'already fixed by #412 — the caller reduces both operands to a keyed HMAC digest',
    impact: { impact: 'token forgery', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
    history: { fixed: 'YES', searched: 'git log -p -- session.py auth.py, CHANGELOG' },
  },
  envelope: { hosts: [], level: 1, destructive: false },
  candidates: [{ description: 'timing oracle', entryPoint: 'POST /login', payload: 'a'.repeat(32) }],
}

const BUILT_POC = {
  built: true,
  executed: true,
  lintPassed: true,
  pocType: 'standalone',
  path: 'poc/x.py',
  absolutePath: '/wt/poc/x.py',
  command: 'python3 /wt/poc/x.py',
  output: 'forged',
  invokedSymbol: 'SessionStore.validate',
}

test('a settled finding spends nothing and is not reported as a bad dispatch', async () => {
  for (const status of SETTLED) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: { ...SETTLED_ARGS, verification: { ...SETTLED_ARGS.verification, status } },
      agents: { build: BUILT_POC },
    })
    assert.equal(result.status, 'BLOCKED', `${status} must not buy a build`)
    assert.equal(calls.length, 0, 'nothing may be spent on a finding Stage 1 already settled')
    assert.equal(result.settledBy, status, 'the orchestrator branches on this field')
    assert.match(result.reason, new RegExp(status), 'the reason must name the verdict it relays')
    // The old message. It sent the orchestrator back to correct a dispatch that
    // was correct, and when that failed it built the exploit by hand instead.
    assert.doesNotMatch(
      result.reason,
      /unusable arg shape|forward triage-static/i,
      'a settled finding is not a defective dispatch and must not be described as one',
    )
    assert.ok(result.deliverable && result.deliverable.trim(), 'the refusal must name what replaces the PoC')
  }
})

test('the relayed reason carries Stage 1s own evidence, not just its status', async () => {
  const { result } = await runScript('triage-poc.js', { args: SETTLED_ARGS, agents: {} })
  assert.match(result.reason, /#412/, "Stage 1's reason is the deciding evidence and must survive")
})

// A dispatch carrying only a settled verification is the shape the arg gate
// handles worst: it answers with a dozen field names and buries the one fact
// that matters. The verdict outranks them because nothing below it runs either
// way.
test('a settled verdict outranks a malformed dispatch', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { verification: { status: 'NOT_EXPLOITABLE', reason: 'blocked at ALLOWED_TERM' } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.settledBy, 'NOT_EXPLOITABLE')
  assert.match(result.reason, /ALLOWED_TERM/)
  assert.equal(calls.length, 0)
})

// The converse, and the guard that the new branch did not swallow the arg gate:
// a status that is NOT a verdict must still get the message that sends the
// caller back.
test('a malformed dispatch Stage 1 did not settle still reports its missing fields', async () => {
  for (const status of ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: { verification: { status } },
      agents: { build: BUILT_POC },
    })
    assert.equal(result.status, 'BLOCKED')
    assert.equal(result.settledBy, undefined, 'this one IS a bad dispatch')
    assert.match(result.reason, /unusable arg shape/)
    assert.equal(calls.length, 0)
  }
})

// --------------------------------------------- SKILL.md has to be able to say it
//
// A gate that produces a verdict the orchestrator has no documented way to
// report is a gate that gets talked around. These tie the prose to the code.

function skillSection(titleMatcher) {
  const section = SKILL_MD.split(/^## /m).find((part) => titleMatcher.test(part.split('\n')[0]))
  assert.ok(section, `SKILL.md has no "## " section whose heading matches ${titleMatcher}`)
  return section
}

test('SKILL.md documents every status triage-poc can return', () => {
  const returned = new Set([...REVIEW_SRC.matchAll(/status: '([A-Z_]+)'/g)].map((m) => m[1]))
  assert.ok(returned.size >= 5, `only found ${returned.size} returned statuses; this scan is stale`)
  for (const status of returned) {
    assert.ok(
      SKILL_MD.includes(`\`${status}\``),
      `triage-poc can return ${status} and SKILL.md never mentions it, so the orchestrator ` +
        `has no documented way to report it. ALREADY_FIXED and NEEDS_MORE_INFO were both live ` +
        `and both absent from the Stage 3 returns list.`,
    )
  }
})

// The DO_NOT_SUBMIT table describes reviewers who ARGUED, and both of its rows
// key on a `reason` prefix. Five agents that never ran produced the byte-identical
// prefix, so an obedient orchestrator reported a built, executed, independently
// verified PoC as FALSE POSITIVE on the strength of nothing anyone said.
test('SKILL.md says a silent challenge agent is not a refutation', () => {
  const section = skillSection(/Verdicts/i)
  assert.match(
    section,
    /no verdict/i,
    'the DO_NOT_SUBMIT table describes reviewers who argued; it has to say what a silent one returns',
  )
  assert.match(section, /NEEDS_MORE_INFO/, 'and name the status Stage 3 returns instead')
})

test('SKILL.md gives every settled verdict an opening line to report it with', () => {
  const section = skillSection(/asked for a PoC/i)
  for (const status of SETTLED) {
    assert.ok(
      section.includes(`\`${status}\``),
      `Stage 3 refuses on ${status} and the refusal section does not say how to report it`,
    )
  }
})

test('the refusal section forbids hand-building and bounds the negative PoC', () => {
  const section = skillSection(/asked for a PoC/i)
  assert.match(section, /by hand/i, 'hand-building after a refusal is the failure mode; name it')
  assert.match(section, /negative PoC/i, 'the legitimate alternative has to be named to be used')
  assert.match(
    section,
    /entry point/i,
    'an unbounded negative PoC is an exploit; it has to be pinned to the entry point',
  )
  assert.match(section, /settledBy/, 'the field the orchestrator branches on must be documented')
})

test('the retraction wording leaves no room to hedge', () => {
  const section = skillSection(/asked for a PoC/i)
  assert.match(section, /do not pay/i)
  // The measured hedge, kept as the counter-example. It is verbatim what the arm
  // with no plugin answers, and three runs that had FOUND the fix still wrote it.
  // Seam-tolerant, per this suite's own lesson about literal multi-word phrases:
  // every inter-word position in prose is a place a line wrap or an emphasis
  // marker can land, and the first draft of this assertion failed on a newline.
  assert.match(
    section,
    /already[-\s*_`]+fixed[-\s*_`]+on[-\s*_`]+current[-\s*_`]+HEAD/i,
    'the baseline sentence is the thing being ruled out; deleting the example deletes the rule',
  )
})

// An off-type boolean is not a hypothetical here: `required` is the only thing
// the runtime validator enforces and `type` is advisory, so `lintExitZero: 'no'`
// is a schema-valid answer. Read by exclusion, every one of these was TRUTHY and
// cleared the gate — a PoC with no file at all, and one whose lint FAILED, each
// reached REPORTED at HIGH confidence, which SKILL.md maps to TRUE POSITIVE.
// `0` fails the other way: it is the exit code of a CLEAN run and is falsy, so a
// reviewer answering the old prompt literally blocked a correct PoC.
test('an off-type artifact boolean blocks rather than clearing', () => {
  for (const field of ['fileExists', 'lintExitZero']) {
    for (const value of ['no', 'false', 'true', '0', 1, 0, {}, []]) {
      assert.ok(
        artifactProblem({ ...cleanCheck, [field]: value }),
        `${field} = ${JSON.stringify(value)} must not clear the artifact gate`,
      )
    }
  }
  assert.equal(artifactProblem(cleanCheck), null, 'a clean check must still pass')
})
