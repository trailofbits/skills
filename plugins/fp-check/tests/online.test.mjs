/**
 * Layer 2 and 2b for Stage 2, which had no tests at all: online-triage shipped as
 * prose with no suite, and the 7-case eval suite cannot measure it — its premise
 * is evidence synthetic fixtures do not have, and its own rule is to stop when
 * offline, so the correct behaviour would score zero.
 *
 * The gates here are therefore the only thing standing behind it, and the one
 * that matters most is `offlineProblem`: as prose, "stop when offline rather than
 * triaging from memory" inverts under pressure, because an agent with no network
 * still has a prompt asking it for a scope verdict and the most likely completion
 * is a plausible one.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const ONLINE = script('triage-online.js')
const missingArgs = loadFn(ONLINE, 'missingArgs')
const offlineProblem = loadFn(ONLINE, 'offlineProblem')
const scopeHalt = loadFn(ONLINE, 'scopeHalt')
const summaryProblem = loadFn(ONLINE, 'summaryProblem')
// `externalRootCause` alongside it: the census gate now reads root cause through
// the predicate the cap reads it through, and `loadFn` evaluates one function
// alone, where a call to a sibling is a ReferenceError.
const { needsUserCensus } = loadFns(ONLINE, 'needsUserCensus', 'externalRootCause')
const censusProblem = loadFn(ONLINE, 'censusProblem')
const stageOneStands = loadFn(ONLINE, 'stageOneStands')
// `namedLevels` alongside it: `capSeverity` calls it, and `loadFn` evaluates one
// function alone, where a call to a sibling is a ReferenceError.
const { capSeverity } = loadFns(ONLINE, 'capSeverity', 'namedLevels', 'externalRootCause')

const GOOD = {
  baseDir: '/plugin/skills/fp-check',
  finding: {
    summary: 'unauthenticated read of arbitrary tables',
    sink: 'search.py:34',
    component: 'the search module',
    claimedImpact: 'database contents disclosed',
  },
  verification: {
    status: 'TRUE_POSITIVE',
    // `result` is required: `impactLine` branches on it, and a dispatch that omits
    // it opens all five prompts with "Stage 1 graded it not at all".
    impact: { result: 'VERIFIED', impact: 'reads arbitrary tables', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
  },
  project: { name: 'example-app', url: 'https://github.com/example/app' },
  sources: [{ label: 'github-advisories', query: 'repo:example/app SQL' }],
}

// ------------------------------------------------------------- missingArgs

test('a well-formed dispatch has no problems', () => {
  assert.deepEqual(missingArgs(GOOD), [])
})

test('the project must be identified: there is nothing to look up without it', () => {
  for (const field of ['name', 'url']) {
    const problems = missingArgs({ ...GOOD, project: { ...GOOD.project, [field]: undefined } })
    assert.ok(problems.includes(`project.${field}`), `project.${field} must be required`)
  }
  // A missing project object must be reported, not thrown on: `project.name` is a
  // nested access in the prompt.
  const problems = missingArgs({ ...GOOD, project: undefined })
  assert.ok(Array.isArray(problems) && problems.length > 0)
})

// Zero sources means the past-bug fan-out is skipped entirely and the summary is
// written as though nothing similar had ever been reported — the same vacuous pass
// an empty `layers` list is in Stage 1.
test('an empty source list is rejected rather than treated as nothing to find', () => {
  const problems = missingArgs({ ...GOOD, sources: [] })
  assert.ok(problems.some((p) => p.startsWith('sources')))
  assert.match(problems.find((p) => p.startsWith('sources')), /duplicate check/)
})

test('a source without a label or a query is rejected', () => {
  for (const field of ['label', 'query']) {
    const sources = [{ ...GOOD.sources[0], [field]: undefined }]
    assert.ok(missingArgs({ ...GOOD, sources }).includes(`sources[0].${field}`))
  }
})

test('a non-array sources list is reported, not thrown on', () => {
  for (const bad of [{ label: 'x' }, 'github', 7]) {
    const problems = missingArgs({ ...GOOD, sources: bad })
    assert.ok(Array.isArray(problems), 'must return, not throw')
    assert.ok(problems.some((p) => p.startsWith('sources')))
  }
})

// A finding already dismissed on the code does not need a policy check, and
// running one anyway invites the online evidence to argue a dead finding back to
// life. NEEDS_MORE_INFO is the one Stage 2 can still move: Stage 1 reaches it both
// before and after the impact agent, so its payload sometimes carries the impact
// this stage requires.
test('only an actionable Stage 1 status is accepted', () => {
  for (const status of ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.deepEqual(problems, [], `${status} must be accepted`)
  }
  for (const status of ['DISMISSED', 'NOT_EXPLOITABLE', 'NOT_VULNERABLE', 'FALSE_POSITIVE', 'ALREADY_FIXED', 'OUT_OF_SCOPE', 'BLOCKED', '', undefined]) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.ok(
      problems.some((p) => p.startsWith('verification.status')),
      `${JSON.stringify(status)} must be rejected`,
    )
  }
})

// Stage 1's own OUT_OF_SCOPE payload, run through Stage 2's validator. Not a
// hand-built fixture: the two scripts have to agree about a value one of them
// produces and the other consumes, and a fixture can be written to agree with
// either.
//
// The status was on the actionable list on the reasoning that "a DECLARED scope is
// exactly what a published policy can overturn" — but Stage 1 decides OUT_OF_SCOPE
// in `decideGate`, before the impact agent is ever dispatched, so the payload it
// returns has no `impact` and no `severity` and Stage 2 requires both. Every
// dispatch the list invited was therefore rejected by the next four lines of the
// same function, and the rejection listed OUT_OF_SCOPE among the statuses it
// accepts.
test('a Stage 1 OUT_OF_SCOPE payload is rejected coherently, not invited and then refused', async () => {
  const staticRun = await runScript('triage-static.js', {
    args: {
      baseDir: '/plugin/skills/fp-check',
      finding: {
        summary: 'unauthenticated read of arbitrary tables',
        sink: 'search.py:34',
        component: 'the search module',
        claimedImpact: 'database contents disclosed',
        bugClass: 'injection',
        threatModel: 'an unauthenticated caller supplies a crafted filter',
      },
      entryPoint: { description: 'GET /search', location: 'search.py:8', payload: "f=1' OR 1=1--" },
      layers: [{ name: 'filter-allowlist', location: 'search.py:14', checks: 'the filter is matched' }],
      scope: 'the API surface, excluding internal tooling',
    },
    agents: {
      layer: { verdict: 'PAYLOAD_REACHES_SINK', evidence: 'the filter reaches the query' },
      recovery: { recoveryExists: false, effectiveImpact: 'rows disclosed', evidence: 'no recover' },
      'threat-model': {
        inScope: 'NO',
        byDesign: false,
        byDesignIndicators: 0,
        evidence: 'internal tooling is excluded by the declared scope',
      },
      history: { fixed: 'NO', complete: false, reference: '', searched: 'git log -p', evidence: 'nothing' },
    },
  })
  assert.equal(staticRun.result.status, 'OUT_OF_SCOPE', 'the fixture must actually be a Stage 1 OUT_OF_SCOPE')
  assert.equal(staticRun.result.severity, undefined, 'and it is decided before any severity exists')

  const problems = missingArgs({ ...GOOD, verification: staticRun.result })
  const rejection = problems.find((p) => p.startsWith('verification.status'))
  assert.ok(rejection, 'Stage 2 must not offer a status whose only possible payload it rejects')
  // The accepted list, not the whole message: naming the status it RECEIVED is the
  // useful half of the rejection. Listing it as acceptable is the incoherent half.
  const accepted = rejection.slice(0, rejection.indexOf('; got'))
  assert.ok(
    !accepted.includes('OUT_OF_SCOPE'),
    `the rejection lists the status it just refused as acceptable: ${accepted}`,
  )
})

test('the validator returns an array and never throws on empty input', () => {
  for (const input of [{}, undefined, { finding: null, verification: null, project: null }]) {
    const out = missingArgs(input)
    assert.ok(Array.isArray(out) && out.length > 0)
  }
})

// ---------------------------------------------------------- offlineProblem

const READ = {
  reachedNetwork: true,
  sourcesRead: 'https://github.com/example/app/blob/main/SECURITY.md',
  inScopeClasses: 'injection, authz bypass',
  outOfScopeClasses: 'DoS, self-XSS',
  evidence: 'read the policy',
}

test('a live fetch with a named source is not a problem', () => {
  assert.equal(offlineProblem(READ), null)
})

test('reachedNetwork false halts, and names where it looked', () => {
  const r = offlineProblem({ ...READ, reachedNetwork: false, sourcesRead: 'tried SECURITY.md, DNS failed' })
  assert.ok(r)
  assert.match(r, /DNS failed/)
})

// Read the affirmative value. Grading by exclusion — anything not `false` counts
// as online — makes an omitted field a successful fetch, which is the exact
// failure this gate exists to stop.
test('anything other than true is offline', () => {
  for (const value of [undefined, null, '', 0, 'yes', 'true', 1]) {
    assert.ok(offlineProblem({ ...READ, reachedNetwork: value }), `reachedNetwork ${JSON.stringify(value)}`)
  }
})

// A dead agent read nothing, which is the same thing as being offline, so the
// failure direction has to be the same.
test('a dead policy agent halts exactly as an offline one does', () => {
  for (const input of [null, undefined]) {
    const r = offlineProblem(input)
    assert.ok(r && r.trim())
  }
})

// "I reached the network" with no citable source is worse than being offline: it
// looks like evidence. `required` validates `sourcesRead: ''`.
test('an uncitable policy claim halts even when the network was reached', () => {
  for (const sourcesRead of [undefined, '', '   ']) {
    const r = offlineProblem({ ...READ, sourcesRead })
    assert.ok(r, `sourcesRead ${JSON.stringify(sourcesRead)} must not pass`)
    assert.match(r, /uncitable|named no source/)
  }
})

// A project that publishes nothing is a DIFFERENT answer from a project that
// could not be reached, and collapsing them would make the halt fire on every
// project without a SECURITY.md.
test('a project that publishes nothing is not the same as being offline', () => {
  const r = offlineProblem({
    ...READ,
    inScopeClasses: '',
    outOfScopeClasses: '',
    sourcesRead: 'checked SECURITY.md (404), the wiki (empty), and the docs site: no policy published',
  })
  assert.equal(r, null)
})

// --------------------------------------------------------------- scopeHalt

const IN_SCOPE = {
  verdict: 'in-scope',
  clause: '"injection in the query layer is in scope"',
  severity: 'High',
  evidence: 'matches the in-scope list',
}

test('in-scope and unclear both continue', () => {
  assert.equal(scopeHalt(IN_SCOPE), null)
  assert.equal(scopeHalt({ ...IN_SCOPE, verdict: 'unclear', clause: '' }), null)
})

test('out-of-scope with a quoted clause halts and quotes it', () => {
  const r = scopeHalt({
    ...IN_SCOPE,
    verdict: 'out-of-scope',
    clause: '"self-XSS is explicitly excluded"',
  })
  assert.equal(r.status, 'OUT_OF_SCOPE')
  assert.match(r.reason, /self-XSS/)
})

// The asymmetry is the whole safety property: out-of-scope is the one verdict
// here that ends the work, so it is the one that has to be earned. "It's probably
// out of scope" is `unclear`, and `unclear` does not stop anything.
test('out-of-scope with no clause is NEEDS MORE INFO, not a halt', () => {
  for (const clause of [undefined, '', '   ']) {
    const r = scopeHalt({ ...IN_SCOPE, verdict: 'out-of-scope', clause })
    assert.equal(r.status, 'NEEDS_MORE_INFO', `clause ${JSON.stringify(clause)} must not close the finding`)
    assert.match(r.reason, /unclear/)
  }
})

test('a dead scope agent blocks rather than continuing on no verdict', () => {
  const r = scopeHalt(null)
  assert.equal(r.status, 'BLOCKED')
  assert.ok(r.reason.trim())
})

// ---------------------------------------------------------- summaryProblem

const SUMMARY = {
  finalSeverity: 'High',
  scopeVerdict: 'in-scope',
  reasoning: 'matches the in-scope list and no past report covers it',
  confidence: 'medium',
  openQuestions: 'the rubric does not say how it rates unauthenticated reads',
  evidence: 'the policy and three searches',
}

test('a complete summary is not a problem', () => {
  assert.equal(summaryProblem(SUMMARY), null)
})

test('an empty openQuestions is rejected: an omitted gap reads as a settled question', () => {
  for (const openQuestions of [undefined, '', '   ']) {
    assert.ok(summaryProblem({ ...SUMMARY, openQuestions }), JSON.stringify(openQuestions))
  }
})

test('an empty reasoning is rejected', () => {
  for (const reasoning of [undefined, '', '   ']) {
    assert.ok(summaryProblem({ ...SUMMARY, reasoning }))
  }
})

test('a dead summary agent is a problem', () => {
  assert.ok(summaryProblem(null))
})

// ------------------------------------------------------- needsUserCensus
//
// The parent's `triage-online-users` role is genuinely conditional: for a bug
// exploitable in the target itself, a census of the project's consumers answers a
// question nobody asked. The condition is code rather than a third question at
// Step 0, because whether severity turns on downstream usage is a finding of the
// reachability analysis, and because a non-interactive harness answers every extra
// question `no` — which is how this plugin shipped three capabilities that fired
// zero times in 63 measured runs.

const IN_REPO = { impact: { rootCause: 'internal', classification: 'vulnerability' } }

test('a bug exploitable in the target itself needs no consumer census', () => {
  assert.equal(needsUserCensus(IN_REPO, REACHED, IN_SCOPE), false)
})

// Widened past the two enum members, and `third-party` is the row that matters:
// the cap reads this same field through `externalRootCause`, so with the
// affirmative pair here a finding was priced as external by 2.4b — the arithmetic
// that made severity turn on downstream usage — while this gate read it as
// in-repo and skipped the census that severity now depended on.
test('a root cause outside this project makes it the client-side that matters', () => {
  for (const rootCause of ['integration', 'external', 'third-party', 'upstream', '', undefined]) {
    const verification = { impact: { rootCause, classification: 'vulnerability' } }
    assert.equal(needsUserCensus(verification, REACHED, IN_SCOPE), true, JSON.stringify(rootCause))
  }
})

// The other direction, so the widening did not become "always census": `internal`
// is the claim that exempts, and it exempts in any casing for the reason the cap
// forgives one.
test('an in-repo root cause still needs no census, in any casing', () => {
  for (const rootCause of ['internal', 'Internal', '  internal  ']) {
    const verification = { impact: { rootCause, classification: 'vulnerability' } }
    assert.equal(needsUserCensus(verification, REACHED, IN_SCOPE), false, JSON.stringify(rootCause))
  }
})

// A hardening gap is by definition not exploitable on its own, so whether it
// matters IS the question about how consumers use it.
test('a hardening gap needs the census even with an in-repo caller', () => {
  const verification = { impact: { rootCause: 'internal', classification: 'hardening_gap' } }
  assert.equal(needsUserCensus(verification, REACHED, IN_SCOPE), true)
})

test('a sink only a consumer can drive needs the census', () => {
  assert.equal(needsUserCensus(IN_REPO, { ...REACHED, driver: 'client-code' }, IN_SCOPE), true)
})

// Read by exclusion, and deliberately the opposite direction from every other
// gate in this file. Elsewhere the risk is a claim made on no evidence, so only
// the affirmative value counts. Here the measured risk is a capability that never
// fires: an omitted `driver` reading as "no census needed" is that failure exactly.
// One wasted agent is the cost of being wrong this way; losing the role again is
// the cost of being wrong the other way.
test('an unsettled or missing driver runs the census rather than skipping it', () => {
  for (const driver of ['unknown', undefined, '', null]) {
    assert.equal(needsUserCensus(IN_REPO, { ...REACHED, driver }, IN_SCOPE), true, `driver ${JSON.stringify(driver)}`)
  }
  assert.equal(needsUserCensus(IN_REPO, null, IN_SCOPE), true, 'a missing reachability result')
})

// Unreachable from the workflow — scopeHalt returned before this — but the
// predicate is unit-tested alone and must not say yes to "census the consumers of
// a project whose policy excludes this finding".
test('an out-of-scope finding gets no census whatever else is true', () => {
  const verification = { impact: { rootCause: 'external', classification: 'hardening_gap' } }
  const out = { ...IN_SCOPE, verdict: 'out-of-scope' }
  assert.equal(needsUserCensus(verification, { ...REACHED, driver: 'client-code' }, out), false)
})

test('the predicate never throws on a missing payload', () => {
  for (const args of [[undefined, undefined, undefined], [null, null, null], [{}, {}, {}]]) {
    assert.equal(typeof needsUserCensus(...args), 'boolean')
  }
})

// --------------------------------------------------------- censusProblem

test('a census that searched a live index is not a problem', () => {
  assert.equal(censusProblem(CENSUS), null)
})

// The same rule as offlineProblem, applied to the one agent whose subject is the
// world: a census that reached nothing must never be summarised as "no consumer
// is affected", which is a positive claim about every consumer there is.
test('a census that could not search halts on the affirmative value', () => {
  for (const value of [undefined, null, false, '', 'yes', 1]) {
    assert.ok(censusProblem({ ...CENSUS, reachedNetwork: value }), `reachedNetwork ${JSON.stringify(value)}`)
  }
})

test('a dead census agent is a problem', () => {
  for (const dead of [null, undefined]) assert.ok(censusProblem(dead))
})

test('a census that names no query it ran is not evidence of absence', () => {
  for (const coverage of [undefined, '', '   ']) {
    const r = censusProblem({ ...CENSUS, coverage })
    assert.ok(r, `coverage ${JSON.stringify(coverage)}`)
    assert.match(r, /uncitable|named no query/)
  }
})

// The asymmetry the enum exists for: `affected-users-found` is a positive claim
// that raises severity, so it has to be earned with a named consumer.
test('affected-users-found with nobody named is a problem', () => {
  for (const confirmed of [undefined, '', '   ']) {
    assert.ok(censusProblem({ ...CENSUS, result: 'affected-users-found', confirmed }), JSON.stringify(confirmed))
  }
  assert.equal(
    censusProblem({ ...CENSUS, result: 'affected-users-found', confirmed: 'acme/widgets calls search(req.query.f) at app.js:88' }),
    null,
  )
})

// --------------------------------------------------- the gates, where used

// The reachability agent has its own schema now: it is asked who drives the sink
// in the published project, and never asked for a policy verdict or a quoted
// clause, which SCOPE_SCHEMA required of it and nothing read.
const REACHED = {
  driver: 'in-repo-caller',
  eligibilityCaveats: 'requires the search endpoint to be exposed publicly',
  evidence: 'reachable from /search',
}

const CENSUS = {
  reachedNetwork: true,
  result: 'no-confirmed-users',
  pattern: 'calling search(filter) with a caller-built filter string',
  coverage: 'GitHub code search for `search(` across the 40 dependents listed on the package index',
  confirmed: '',
  severityEffect: 'lower',
  evidence: 'every dependent read passes a constant',
}

const agents = (over = {}) => ({
  policy: READ,
  reachability: REACHED,
  inscope: IN_SCOPE,
  'downstream-users': CENSUS,
  'past-bugs': {
    result: 'nothing',
    coverage: 'searched all 3 pages of the advisory list',
    recommendedSeverity: 'Unknown',
    duplicate: false,
    evidence: 'no similar advisory',
  },
  summary: SUMMARY,
  ...over,
})

test('the happy path reaches TRIAGED through every role', async () => {
  const { result, calls } = await runScript('triage-online.js', { args: GOOD, agents: agents() })
  assert.equal(result.status, 'TRIAGED')
  for (const label of ['policy', 'reachability', 'inscope', 'summary']) {
    assert.ok(calls.some((c) => c.label === label), `${label} must be dispatched`)
  }
  assert.ok(calls.some((c) => c.label === 'past-bugs:github-advisories'))
})

// The measured failure this whole stage is built against: without the gate, an
// offline agent still has a prompt asking for a scope verdict, and it answers.
test('an offline policy agent halts before a single scope claim is made', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ policy: { ...READ, reachedNetwork: false, sourcesRead: 'no network' } }),
  })
  assert.equal(result.status, 'OFFLINE')
  assert.ok(
    !calls.some((c) => c.label === 'inscope'),
    'no scope verdict may be formed without a document to form it from',
  )
  assert.ok(!calls.some((c) => c.label === 'summary'))
})

test('a dead policy agent halts the same way', async () => {
  const { result } = await runScript('triage-online.js', { args: GOOD, agents: agents({ policy: null }) })
  assert.equal(result.status, 'OFFLINE')
})

test('an out-of-scope verdict halts before the past-bug fan-out is paid for', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '"the search module is out of scope"' },
    }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE')
  assert.ok(!calls.some((c) => c.label.startsWith('past-bugs:')))
})

test('an unclaused out-of-scope does not halt the finding', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /unclear/)
})

test('a confirmed public duplicate is reported as one', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: 'GHSA-xxxx-yyyy-zzzz',
        similarity: 'same trigger, same actor, same component',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'identical report',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.match(result.reason, /GHSA-/)
})

// DUPLICATE returns BEFORE the summary gate on purpose, and it was the one
// non-BLOCKED terminal status carrying a `summary` and no corrected severity — so
// the pre-cap `summary.finalSeverity` was the only number a reader could reach,
// on the very root cause the cap exists for.
test('a terminal duplicate carries the CAPPED severity, not the summary agent number', async () => {
  const { result } = await runScript('triage-online.js', {
    args: {
      ...GOOD,
      verification: {
        ...GOOD.verification,
        impact: { ...GOOD.verification.impact, rootCause: 'integration' },
      },
    },
    agents: agents({
      summary: { ...SUMMARY, finalSeverity: 'Critical' },
      'past-bugs': { result: 'similar-bugs-found', coverage: 'all pages', links: 'GHSA-xxxx-yyyy-zzzz', recommendedSeverity: 'High', duplicate: true, evidence: 'identical report' },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.equal(result.severity, 'Medium', 'the integration cap is not applied on the duplicate path')
  assert.match(result.severityCorrection, /integration/)
})

// The same fallback the `Unknown` branch has, for the same reason and reached the
// same way. This stage exists to narrow or correct Stage 1's rating; a
// `finalSeverity` naming two levels does neither, and SKILL.md tells the
// orchestrator to take the reported severity from here — so without the fallback
// `Medium/High` was the number the finding shipped with, uncapped, on the very
// root cause the cap exists for.
test('a finalSeverity naming two levels falls back to Stage 1 rather than shipping', async () => {
  const { result } = await runScript('triage-online.js', {
    args: {
      ...GOOD,
      verification: {
        ...GOOD.verification,
        severity: 'Medium',
        impact: { ...GOOD.verification.impact, rootCause: 'integration' },
      },
    },
    agents: agents({ summary: { ...SUMMARY, finalSeverity: 'Critical (affects low-privilege users)' } }),
  })
  assert.equal(result.severity, 'Medium', "the summary agent's unreadable rating was adopted")
  assert.match(result.severityCorrection, /names 2 levels/)
  assert.match(result.severityCorrection, /Stage 1/)
  // and the substitution is stated where the reader sees the reasoning it corrects
  assert.match(result.reason, /names 2 levels/)
})

// The third shape of the same fallback. 'n/a', 'TBD' and 'P1' name no level, so
// the cap read them as below itself and let them through: the finding shipped
// with a string as its rating, and the only branch that caught this shape was the
// literal-'Unknown' one beside it.
test('a finalSeverity naming no level falls back to Stage 1 rather than shipping', async () => {
  for (const finalSeverity of ['n/a', 'TBD', 'P1']) {
    const { result } = await runScript('triage-online.js', {
      args: {
        ...GOOD,
        verification: {
          ...GOOD.verification,
          severity: 'Medium',
          impact: { ...GOOD.verification.impact, rootCause: 'integration' },
        },
      },
      agents: agents({ summary: { ...SUMMARY, finalSeverity } }),
    })
    assert.equal(result.severity, 'Medium', `${finalSeverity} was adopted as the reported rating`)
    assert.match(result.severityCorrection, /names none of/)
    assert.match(result.severityCorrection, /Stage 1/)
    assert.match(result.reason, /names none of/)
  }
})

// Stage 2 carries its own copy of the cap, because this stage's census fires
// precisely on the capped root causes and its `severityEffect: raise` invites the
// number back up. The workflow-level test above proves the copy is WIRED; these
// prove it decides the same way as Stage 1's, which is the half that drifted —
// the copy had no direct test at all while the other two did.
test('the online cap decides on one named level and refuses to guess at two', () => {
  // Caps: exactly one level named, above the cap. Word boundaries are what stop
  // `low` inside "Allowlist" from making a High uncappable.
  for (const severity of ['Allowlist bypass — High', 'Critical (RCE)', 'CRITICAL', 'critical', 'High']) {
    const r = capSeverity(severity, 'integration', 'vulnerability')
    assert.equal(r.severity, 'Medium', `${severity} must not escape the cap`)
    assert.match(r.note, /2\.4b/)
    assert.equal(r.ambiguous, '')
  }
  // Refuses: two levels named. Round 7 read the highest and applied it only where
  // it lowered, which let every one of these ship UNCHANGED — `Medium/High`
  // uncapped, and `Critical (affects low-privilege users)` uncapped because the
  // word `low` appears in "low-privilege".
  for (const severity of [
    'Medium/High',
    'Medium-High',
    'High/Critical',
    'Critical (affects low-privilege users)',
    'Low (the affected path is not business-critical)',
    'Informational (no high-value data)',
    'Critically low impact — Informational',
  ]) {
    const r = capSeverity(severity, 'integration', 'vulnerability')
    assert.ok(r.ambiguous, `${severity} names two levels and must be refused, not guessed at`)
    assert.equal(r.severity, severity)
    assert.equal(r.note, '')
  }
})

// A cap that raises is not a cap. Word boundaries are what stop 'highly' reading
// as a rating on a finding whose only stated level is Low.
test('the online cap never raises a severity below it', () => {
  for (const severity of ['Medium', 'Low', 'Informational', 'Low — highly situational', 'Highly situational, ultimately Low']) {
    const r = capSeverity(severity, 'external', 'hardening_gap')
    assert.equal(r.severity, severity, `${severity} must not be raised`)
    assert.equal(r.note, '')
    assert.equal(r.ambiguous, '')
  }
})

// `out-of-scope` is withheld from SUMMARY_SCHEMA's enum, and an enum is not a
// gate: `required` is the only thing the runtime validator enforces. So the one
// verdict that ends the analysis — which SCOPE_SCHEMA makes cost a quoted clause —
// could still be written here, where there is no clause field, and SKILL.md read
// the scope from `summary`. It printed "OUT OF SCOPE" with nothing after the dash.
test('an out-of-scope written by the summary agent is not adopted', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ summary: { ...SUMMARY, scopeVerdict: 'out-of-scope' } }),
  })
  assert.equal(result.status, 'TRIAGED')
  assert.equal(result.scopeVerdict, 'unclear', 'the terminal verdict was taken from a schema nothing enforces')
})

test('the top-level scopeVerdict is what an in-scope summary produces too', async () => {
  const { result } = await runScript('triage-online.js', { args: GOOD, agents: agents() })
  assert.equal(result.scopeVerdict, 'in-scope')
})

// Zero results is not "nothing was found": it is "nothing was searched". The
// summary prompt asserted the first, which is the same vacuous pass `missingArgs`
// refuses an empty `sources` list for.
test('a past-bug fan-out that returned nothing at all is not summarised as no duplicate', async () => {
  const { calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ 'past-bugs': null }),
  })
  const summary = calls.find((c) => c.label === 'summary')
  assert.ok(!/No source reported this as an existing duplicate/.test(summary.prompt))
  assert.match(summary.prompt, /the duplicate check did not happen/)
})

// A source whose agent died was NOT searched, and "not searched" summarised as
// "nothing found there" is how an absent duplicate check becomes a clean bill of
// health. Reported rather than fatal: the other sources are still evidence.
test('a dead source agent is reported to the summary as unchecked', async () => {
  const sources = [
    { label: 'github-advisories', query: 'a' },
    { label: 'mailing-list', query: 'b' },
  ]
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents({
      'past-bugs': (prompt) =>
        prompt.includes('mailing-list')
          ? null
          : {
              result: 'nothing',
              coverage: 'all pages',
              recommendedSeverity: 'Unknown',
              duplicate: false,
              evidence: 'none',
            },
    }),
  })
  assert.equal(result.status, 'TRIAGED')
  assert.deepEqual(result.unsearched, ['mailing-list'])
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /NOT searched/)
  assert.match(summary.prompt, /mailing-list/)
})

// The one agent result in this script that nothing guarded. `policy` has
// offlineProblem, `scope` has scopeHalt, `summary` has summaryProblem — and
// `reachability.evidence` is interpolated straight into the scope prompt, so a dead
// reachability agent threw a TypeError out of the workflow instead of returning a
// status. An exception is not a fail-closed outcome: the orchestrator is left
// holding a user request with no verdict, which is the documented shape of this
// plugin's worst measured failure (the gate stops, the orchestrator triages by
// hand outside it).
test('a dead reachability agent returns BLOCKED rather than throwing', async () => {
  for (const dead of [null, undefined]) {
    const { result, calls } = await runScript('triage-online.js', {
      args: GOOD,
      agents: agents({ reachability: dead }),
    })
    assert.equal(result.status, 'BLOCKED', `reachability ${JSON.stringify(dead)}`)
    assert.match(result.reason, /reachability/)
    assert.ok(
      !calls.some((c) => c.label === 'inscope'),
      'no scope verdict may be formed against a reachability finding that does not exist',
    )
  }
})

// A duplicate is a fact one of the past-bug agents established, with a link. The
// summary's job is to write it up; its failure cannot unmake it. Ordered the other
// way round, a summary that left openQuestions empty — the single most likely
// summary defect, which is why the gate exists — turned "this is already publicly
// reported at GHSA-x" into "needs more info", and the next reader pays for the
// whole stage again to be told the same thing.
test('a confirmed duplicate survives a summary that fails its own gate', async () => {
  for (const summary of [{ ...SUMMARY, openQuestions: '' }, null]) {
    const { result } = await runScript('triage-online.js', {
      args: GOOD,
      agents: agents({
        summary,
        'past-bugs': {
          result: 'similar-bugs-found',
          coverage: 'all pages',
          links: 'GHSA-xxxx-yyyy-zzzz',
          similarity: 'same trigger, same actor, same component',
          recommendedSeverity: 'High',
          duplicate: true,
          evidence: 'identical report',
        },
      }),
    })
    assert.equal(result.status, 'DUPLICATE', `summary ${JSON.stringify(summary)}`)
    assert.match(result.reason, /GHSA-/)
  }
})

// `evidence` is REQUIRED of every past-bug return, so a `dupCite` that accepted
// any non-blank string made `cited` a filter nothing could fail: one agent's hunch
// ended the stage as a TERMINAL retraction, decided ahead of the summary gate, with
// no link — while SKILL.md reports DUPLICATE as a retraction "with their reference"
// and the orchestrator relays the reason verbatim. The other two retraction sites
// hold the same claim to `citedReference`; this one now does too.
test('an uncited duplicate claim does not retract the finding', async () => {
  const claims = [
    'I believe this is the same class of issue as one discussed on the mailing list',
    'looks like the same thing',
  ]
  for (const evidence of claims) {
    const { result } = await runScript('triage-online.js', {
      args: GOOD,
      agents: agents({
        'past-bugs': {
          result: 'similar-bugs-found',
          coverage: 'searched page 1',
          links: '',
          similarity: 'feels familiar',
          recommendedSeverity: 'High',
          duplicate: true,
          evidence,
        },
      }),
    })
    assert.equal(result.status, 'TRIAGED', JSON.stringify(evidence))
  }
})

// The half that stops the fix from being over-applied. Refusing the retraction must
// not delete the claim: `dupCite` returning null now means "what it said points at
// nothing anyone can look up", not "it said nothing", and the summary agent is the
// one reader that can put that in openQuestions.
test('an uncited duplicate still reaches the summary agent as a claim', async () => {
  const { calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'searched page 1',
        links: '',
        similarity: 'feels familiar',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'the same class of issue was discussed on the mailing list',
      },
    }),
  })
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /the same class of issue was discussed on the mailing list/)
  assert.match(summary.prompt, /NO citable reference/)
  assert.match(summary.prompt, /openQuestions/)
})

// The deliberate semantic change, pinned in both directions: `dupCite` was
// "whichever field is FILLED" and is now "whichever field is CITABLE", so prose in
// `links` no longer displaces a real reference sitting in `evidence`.
test('the citation is taken from whichever field carries one', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: 'see the mailing list thread',
        similarity: 'same trigger',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'https://github.com/example/app/issues/9',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.match(result.reason, /issues\/9/)
})

// The citation a retraction is relayed with, and `required` checks presence and not
// content: `links: '   '` is schema-valid and truthy, so it displaced the `evidence`
// it was meant to fall back to and DUPLICATE came back citing blank space. It now
// proves something strictly stronger — the fallback happens AND the fallback target
// is itself citable.
test('a whitespace links field falls back to the evidence, not to nothing', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: '   ',
        similarity: 'same trigger, same actor',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'filed as issue 1204 in 2019',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.match(result.reason, /issue 1204/)
})

// Over-cap sources are dropped silently as far as every consumer is concerned: the
// cap is logged, and the log is not evidence anyone downstream reads. The summary
// agent is handed "N of M sources returned a result" with the dropped venues absent
// from both numbers, so an unsearched venue reads as a searched one — the same
// "absent duplicate check becomes a clean bill of health" the dead-agent list above
// exists to prevent, arriving by a different route.
test('sources dropped by the cap are declared unchecked, not silently omitted', async () => {
  const sources = Array.from({ length: 8 }, (_, i) => ({ label: `src-${i}`, query: `q${i}` }))
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents(),
  })
  assert.equal(result.status, 'TRIAGED')
  assert.deepEqual(result.beyondCap, ['src-6', 'src-7'], 'the payload must name what was never dispatched')
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /src-6/)
  assert.match(summary.prompt, /src-7/)
})

test('the past-bug fan-out is capped, and what was dropped is logged', async () => {
  const sources = Array.from({ length: 9 }, (_, i) => ({ label: `src-${i}`, query: `q${i}` }))
  const { calls, logs } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents(),
  })
  const searched = calls.filter((c) => c.label.startsWith('past-bugs:'))
  assert.equal(searched.length, 6, 'MAX_SOURCES bounds the fan-out')
  // A silent cap reads as "covered everything".
  assert.ok(logs.some((l) => l.includes('NOT searched')), `the drop must be logged; logs were: ${logs}`)
})

test('a bad arg shape returns BLOCKED without spending an agent', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources: [] },
    agents: agents(),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0)
})

test('an incomplete summary is NEEDS MORE INFO, not a triage result', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ summary: { ...SUMMARY, openQuestions: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
})

// The census, where it is used. `needsUserCensus` being right is worth nothing if
// nothing dispatches on it — that is the shape of every capability this plugin has
// lost: present, correct, covered, and never reached.

const CLIENT_DRIVEN = {
  ...GOOD,
  verification: {
    ...GOOD.verification,
    impact: { result: 'VERIFIED', impact: 'a caller-built filter reaches the query', rootCause: 'integration', classification: 'vulnerability' },
  },
}

test('the census is dispatched when severity turns on how consumers use the project', async () => {
  const { result, calls } = await runScript('triage-online.js', { args: CLIENT_DRIVEN, agents: agents() })
  assert.equal(result.status, 'TRIAGED')
  assert.ok(calls.some((c) => c.label === 'downstream-users'), 'the census agent was never dispatched')
  assert.equal(result.census.state, 'performed')
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /Downstream-consumer census: no-confirmed-users/)
  // Absence of hits is not proof no consumer is affected, and the summary must
  // not be free to read it that way.
  assert.match(summary.prompt, /NOT proof that no consumer is affected/)
})

test('a confirmed affected consumer reaches the summary with its link', async () => {
  const { calls, result } = await runScript('triage-online.js', {
    args: CLIENT_DRIVEN,
    agents: agents({
      'downstream-users': {
        ...CENSUS,
        result: 'affected-users-found',
        confirmed: 'acme/widgets passes req.query.f straight to search() — app.js:88',
        severityEffect: 'raise',
      },
    }),
  })
  assert.equal(result.census.state, 'performed')
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /acme\/widgets/)
  assert.match(summary.prompt, /severityEffect raise/)
})

// A silent skip is how `beyondCap` went wrong: it was logged, and a log is not
// something any consumer reads, so the summary saw an absence and read it as a
// clean result. Logged AND carried, both asserted.
test('a skipped census is logged and carried, not silently absent', async () => {
  const { result, calls, logs } = await runScript('triage-online.js', { args: GOOD, agents: agents() })
  assert.equal(result.status, 'TRIAGED')
  assert.ok(!calls.some((c) => c.label === 'downstream-users'), 'the census was paid for on a directly exploitable bug')
  assert.equal(result.census.state, 'not-applicable')
  assert.match(result.census.why, /in-repo-caller/)
  assert.ok(logs.some((l) => /census not-applicable/.test(l)), `the skip must be logged; logs were: ${logs}`)
  assert.match(calls.find((c) => c.label === 'summary').prompt, /census: not applicable/)
})

// The one thing that must not happen: a census that searched nothing summarised
// as "no consumer is affected". Reported unchecked rather than halting the stage —
// a completed policy read, scope verdict and past-bug fan-out are still evidence,
// and `unsearched` already sets that precedent for this stage.
test('a census that could not search is reported unchecked, never as a clean result', async () => {
  for (const dead of [null, { ...CENSUS, reachedNetwork: false, coverage: 'the code-search API refused every request' }]) {
    const { result, calls } = await runScript('triage-online.js', {
      args: CLIENT_DRIVEN,
      agents: agents({ 'downstream-users': dead }),
    })
    assert.equal(result.status, 'TRIAGED', `census ${JSON.stringify(dead)}`)
    assert.equal(result.census.state, 'unperformed')
    const summary = calls.find((c) => c.label === 'summary').prompt
    assert.match(summary, /census: NOT PERFORMED/)
    assert.match(summary, /UNCHECKED rather than clear/)
    assert.ok(!/no-confirmed-users/.test(summary), 'a census that searched nothing reached the summary as a result')
  }
})

test('the census state is carried on a terminal duplicate too', async () => {
  const { result } = await runScript('triage-online.js', {
    args: CLIENT_DRIVEN,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: 'GHSA-xxxx-yyyy-zzzz',
        similarity: 'same trigger, same actor',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'identical report',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.equal(result.census.state, 'performed')
})

// ------------------------------------------------------- stageOneStands
//
// Stage 2 is optional and can only narrow or correct Stage 1. Before these, all
// five of its non-terminal exits returned a bare status with no severity and no
// field naming the verdict they were handed — so a summary agent that left
// `openQuestions` empty printed NEEDS MORE INFO over a TRUE_POSITIVE established
// from the code. Nothing asserted on those returns' payloads at all, which is how
// the shape shipped.

test('the Stage 1 verdict and its number are what stands', () => {
  assert.deepEqual(stageOneStands(GOOD), { stageOneStatus: 'TRUE_POSITIVE', severity: 'High' })
  assert.deepEqual(
    stageOneStands({ ...GOOD, verification: { ...GOOD.verification, status: 'NEEDS_MORE_INFO', severity: 'Medium' } }),
    { stageOneStatus: 'NEEDS_MORE_INFO', severity: 'Medium' },
  )
})

// `{}` and not a set of undefined keys: the spread has to be a no-op, or a
// malformed dispatch manufactures `stageOneStatus: undefined` and SKILL.md's
// "absent means no verdict was forwarded" rule reads it as present.
test('nothing stands when no Stage 1 verdict was forwarded', () => {
  for (const verification of [undefined, {}, { status: 'FALSE_POSITIVE' }, { status: '' }, { status: '  ' }, { status: 7 }]) {
    assert.deepEqual(stageOneStands({ ...GOOD, verification }), {}, JSON.stringify(verification))
  }
  assert.deepEqual(stageOneStands(undefined), {})
})

test('the carried keys cannot clobber the status or the reason', () => {
  assert.ok(Object.keys(stageOneStands(GOOD)).every((k) => ['stageOneStatus', 'severity'].includes(k)))
})

test('a forwarded verdict with no number still stands', () => {
  const { severity, ...verification } = GOOD.verification
  assert.deepEqual(stageOneStands({ ...GOOD, verification }), { stageOneStatus: 'TRUE_POSITIVE' })
})

test('an offline run leaves the Stage 1 verdict standing', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ policy: { ...READ, reachedNetwork: false, sourcesRead: 'no network' } }),
  })
  assert.equal(result.status, 'OFFLINE')
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

test('a dead reachability agent leaves the Stage 1 verdict standing', async () => {
  const { result } = await runScript('triage-online.js', { args: GOOD, agents: agents({ reachability: null }) })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

test('a dead scope agent leaves the Stage 1 verdict standing', async () => {
  const { result } = await runScript('triage-online.js', { args: GOOD, agents: agents({ inscope: null }) })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

test('an unclaused out-of-scope leaves the Stage 1 verdict standing', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

// The measured failure, pinned: this is the single defect `summaryProblem` exists
// to catch, and it was the one that overwrote a TRUE_POSITIVE.
test('a summary that left openQuestions empty leaves the Stage 1 verdict standing', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ summary: { ...SUMMARY, openQuestions: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /openQuestions/)
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

test('an unusable arg shape still carries the verdict it was handed', async () => {
  const { result } = await runScript('triage-online.js', { args: { ...GOOD, sources: [] }, agents: agents() })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(result.stageOneStatus, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'High')
})

// The other direction. A dispatch with no usable Stage 1 verdict has nothing to
// stand on, and must carry nothing rather than manufacture one.
test('a malformed dispatch manufactures no verdict', async () => {
  for (const verification of [undefined, { ...GOOD.verification, status: 'FALSE_POSITIVE' }]) {
    const { result } = await runScript('triage-online.js', { args: { ...GOOD, verification }, agents: agents() })
    assert.equal(result.status, 'BLOCKED')
    assert.equal(result.stageOneStatus, undefined, JSON.stringify(verification))
    assert.equal(result.severity, undefined)
  }
})

// The guard at the scopeHalt call site, pinned: OUT_OF_SCOPE is this stage
// ANSWERING, so it carries neither. Remove the guard and this goes red.
test('a terminal out-of-scope carries neither the verdict nor a number', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '"the search module is out of scope"' } }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE')
  assert.equal(result.stageOneStatus, undefined)
  assert.equal(result.severity, undefined)
})

// The two terminal statuses that DO answer keep `severity` meaning the CORRECTED
// number, not Stage 1's raw one.
test('the terminal answers keep their own corrected severity', async () => {
  const { result: dup } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: 'GHSA-xxxx-yyyy-zzzz',
        similarity: 'same trigger, same actor',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'identical report',
      },
    }),
  })
  assert.equal(dup.status, 'DUPLICATE')
  assert.equal(dup.severity, 'High')
  assert.equal(dup.stageOneStatus, undefined)

  const { result: triaged } = await runScript('triage-online.js', { args: GOOD, agents: agents() })
  assert.equal(triaged.status, 'TRIAGED')
  assert.equal(triaged.severity, 'High')
  assert.equal(triaged.stageOneStatus, undefined)
})

// The forwarding relays, it does not upgrade.
test('a Stage 1 NEEDS_MORE_INFO stands as itself, not as a confirmation', async () => {
  const { result } = await runScript('triage-online.js', {
    args: { ...GOOD, verification: { ...GOOD.verification, status: 'NEEDS_MORE_INFO', severity: 'Medium' } },
    agents: agents({ policy: { ...READ, reachedNetwork: false, sourcesRead: 'no network' } }),
  })
  assert.equal(result.status, 'OFFLINE')
  assert.equal(result.stageOneStatus, 'NEEDS_MORE_INFO')
  assert.equal(result.severity, 'Medium')
})

test('every gate function is extractable: a rename must fail loudly', () => {
  const names = ['missingArgs', 'offlineProblem', 'scopeHalt', 'summaryProblem', 'needsUserCensus', 'censusProblem', 'stageOneStands']
  const loaded = loadFns(ONLINE, ...names)
  for (const name of names) {
    assert.equal(typeof loaded[name], 'function', `${name} is not extractable`)
  }
})
