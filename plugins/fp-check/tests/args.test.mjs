import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, loadFns, script } from './extract.mjs'

// `auditedSearch` alongside it: `missingArgs` now reads the layers declaration
// through that sibling, and `loadFn` evaluates one function alone, where a call
// to a sibling is a ReferenceError.
const { missingArgs } = loadFns(script('triage-static.js'), 'missingArgs', 'auditedSearch')

const GOOD = {
  baseDir: '/plugin/skills/fp-check',
  finding: {
    summary: 'SQL injection in search',
    sink: 'search.py:34',
    component: 'search module',
    claimedImpact: 'unauthenticated read of arbitrary tables',
    bugClass: 'SQL injection',
    threatModel: 'unauthenticated remote caller of /search reads arbitrary tables',
  },
  entryPoint: {
    description: 'HTTP GET /search?q=',
    location: 'search.py:17',
    payload: "' UNION SELECT username, password FROM users --",
  },
  layers: [{ name: 'ALLOWED_TERM', location: 'search.py:20' }],
  scope: 'search module',
}

test('a well-formed dispatch has no problems', () => {
  assert.deepEqual(missingArgs(GOOD), [])
})

// This is the exact payload the orchestrator sent on the first live run. Every
// one of these near-misses reached an agent as the literal text "undefined".
test('the shape the orchestrator actually invented is rejected', () => {
  const observed = {
    baseDir: '/plugin/skills/fp-check',
    finding: {
      title: 'SQL injection via string concatenation in run_query()',
      cwe: 'CWE-89',
      sink: 'search.py:34',
      rootCause: 'term interpolated rather than bound',
      initialImpactClaim: 'unauthenticated read of arbitrary tables',
      reportedBy: 'user',
    },
    entryPoint: {
      function: 'handle_search(request_args)',
      location: 'search.py:17',
      taintedInput: 'request_args["q"]',
      exampleInput: '{"q": "\' UNION SELECT ..."}',
    },
    layers: [{ id: 1, name: 'ALLOWED_TERM regex allowlist', location: 'search.py:20' }],
    scope: { module: 'search' },
  }
  const problems = missingArgs(observed)
  assert.ok(problems.length > 0, 'the observed bad shape must be rejected')
  for (const expected of [
    'finding.summary',
    'finding.component',
    'finding.claimedImpact',
    'entryPoint.description',
    'entryPoint.payload',
  ]) {
    assert.ok(problems.includes(expected), `${expected} should be reported missing`)
  }
  assert.ok(
    problems.some((p) => p.startsWith('scope')),
    'an object scope must be rejected: it interpolates as [object Object]',
  )
})

// The largest measured source of variance in this plugin, and it had no test.
// `baseDir` is model-supplied; only its PRESENCE was validated. On a 3-run sweep
// of `integration-cap` with identical input, two runs passed the target repo's
// path and one passed the plugin's — the first two could not read a single
// reference file and scored 0.000 and 0.333 against the third's 1.000. All three
// impact agents returned the same correct `Medium / integration`; the difference
// was entirely which files the agents downstream could open.
test('a baseDir that is not the skill directory is rejected', () => {
  const wrong = [
    // The two shapes actually observed in the failing runs: the eval's working
    // directory, which is the TARGET repo and has no references/ in it.
    '/private/var/folders/T/claude-eval-VYuPfq/cwd',
    '/Users/someone/code/target-repo',
    // Relative, which resolves against whatever the agent's cwd happens to be.
    'skills/fp-check',
    './skills/fp-check',
    // Right tail, wrong plugin.
    '/plugin/skills/concept-prover',
  ]
  for (const baseDir of wrong) {
    const problems = missingArgs({ ...GOOD, baseDir })
    assert.ok(
      problems.some((p) => p.startsWith('baseDir')),
      `${baseDir} must be rejected: every reference read would 404 and each agent would answer from memory`,
    )
  }
})

test('the skill directory itself is accepted, with or without a trailing slash', () => {
  for (const baseDir of [
    '/plugin/skills/fp-check',
    '/plugin/skills/fp-check/',
    '/Users/x/.claude/plugins/cache/trailofbits/fp-check/2.5.0/skills/fp-check',
  ]) {
    assert.deepEqual(missingArgs({ ...GOOD, baseDir }), [], baseDir)
  }
})

// Absence and wrong-shape are different messages, and both have to be reported:
// the guard is additive to `need`, not a replacement for it.
test('an absent baseDir is still reported as absent', () => {
  const { baseDir, ...rest } = GOOD
  void baseDir
  assert.ok(missingArgs(rest).includes('baseDir'))
  assert.ok(missingArgs({ ...GOOD, baseDir: '   ' }).some((p) => p.startsWith('baseDir')))
})

test('an object scope is rejected, a string scope is fine', () => {
  assert.ok(missingArgs({ ...GOOD, scope: { module: 'x' } }).some((p) => p.startsWith('scope')))
  assert.deepEqual(missingArgs({ ...GOOD, scope: 'anything' }), [])
})

test('an absent scope is rejected — checkpoint 3.1 is about that input', () => {
  // It used to be optional, and the threat-model prompt covered for it with
  // "none declared — report UNCERTAIN rather than assuming". That is a prompt,
  // and an agent that answered YES anyway returned PROCEED on a finding whose
  // scope nobody had stated.
  const { scope, ...rest } = GOOD
  void scope
  assert.ok(missingArgs(rest).some((p) => p.startsWith('scope')))
  assert.ok(missingArgs({ ...GOOD, scope: '   ' }).some((p) => p.startsWith('scope')))
})

test('each required field is individually load-bearing', () => {
  for (const key of ['summary', 'sink', 'component', 'claimedImpact']) {
    const bad = { ...GOOD, finding: { ...GOOD.finding, [key]: undefined } }
    assert.ok(missingArgs(bad).includes(`finding.${key}`), `finding.${key} must be required`)
  }
  for (const key of ['description', 'location', 'payload']) {
    const bad = { ...GOOD, entryPoint: { ...GOOD.entryPoint, [key]: undefined } }
    assert.ok(missingArgs(bad).includes(`entryPoint.${key}`), `entryPoint.${key} must be required`)
  }
})

test('an empty string counts as missing, not as present', () => {
  const bad = { ...GOOD, finding: { ...GOOD.finding, summary: '' } }
  assert.ok(missingArgs(bad).includes('finding.summary'))
})

test('missing baseDir is reported — without it references cannot resolve', () => {
  const { baseDir, ...rest } = GOOD
  void baseDir
  assert.ok(missingArgs(rest).includes('baseDir'))
})

test('a malformed layer is reported by index', () => {
  const bad = { ...GOOD, layers: [{ name: 'ok', location: 'a.py:1' }, { name: 'no location' }] }
  assert.ok(missingArgs(bad).includes('layers[1].location'))
})

// Checkpoint 2.2 is the one the phase map marks MOST CRITICAL, and it is the
// one that fails open: `layers` defaults to [] in the destructure, so omitting
// the field dispatches zero layer agents, leaves the gate with nothing to fail
// on, and returns PROCEED having inspected nothing. 2.2 does allow "confirmed
// none exist" — confirmed by an agent reading the code, not by an empty array.
test('an omitted layers field is rejected, not defaulted to none', () => {
  const { layers, ...rest } = GOOD
  void layers
  assert.ok(rest.layers === undefined)
  assert.ok(missingArgs(rest).some((p) => p.startsWith('layers')))
  assert.ok(missingArgs({ ...GOOD, layers: null }).some((p) => p.startsWith('layers')))
})

// SKILL.md says the cap "fails closed rather than reporting a partial check as
// complete". It did — but only after dispatching 4 layer agents plus recovery
// and threat-model on a finding it was always going to block. Failing closed
// before the spend is what the sentence promises.
test('more layers than the cap is rejected before any agent is spent', () => {
  const many = Array.from({ length: 5 }, (_, i) => ({ name: `l${i}`, location: `a.py:${i}` }))
  const problem = missingArgs({ ...GOOD, layers: many }).find((p) => p.startsWith('layers'))
  assert.ok(problem, '5 layers must be rejected at the arg gate')
  assert.match(problem, /at most 4/)
  assert.match(problem, /narrow the attack path or split the finding/)
})

test('exactly the cap is accepted', () => {
  const four = Array.from({ length: 4 }, (_, i) => ({ name: `l${i}`, location: `a.py:${i}` }))
  assert.deepEqual(missingArgs({ ...GOOD, layers: four }), [], 'the cap itself is not over it')
})

test('the cap is a parameter, so the gate and the dispatch cap cannot drift', () => {
  const two = [
    { name: 'a', location: 'a.py:1' },
    { name: 'b', location: 'b.py:1' },
  ]
  assert.deepEqual(missingArgs({ ...GOOD, layers: two }, 2), [])
  assert.ok(missingArgs({ ...GOOD, layers: two }, 1).some((p) => p.startsWith('layers')))
})

// Destructuring the problem throws ERR_INVALID_ARG_TYPE if the filter came back
// empty, so this also asserts that an empty list IS rejected. A validator that
// rejects without saying what would be accepted just moves the guessing, and
// the orchestrator cannot ask the user once dispatched.
test('an empty layers list is rejected, and the message says what to send instead', () => {
  const [problem] = missingArgs({ ...GOOD, layers: [] }).filter((p) => p.startsWith('layers'))
  assert.match(problem, /layersSearched/)
})

// The second half of checkpoint 2.2 — "identified at least 1 layer OR CONFIRMED
// NONE EXIST" — which had no way to be said. The old message told the caller to
// pass the absence AS a layer, and the 2.3.0 probe measured what that costs: on
// `integration-cap`, where nothing on the path validates anything, the
// orchestrator did as instructed, an agent had to rule on whether a layer that
// does not exist stops the payload, and it answered with the stopping verdict and
// a reason saying it meant the opposite. The finding died before the impact agent
// and the severity cap never ran.
test('layers: [] is accepted when the caller says what it read and did not find', () => {
  const declared = {
    ...GOOD,
    layers: [],
    layersSearched: 'read charge.py, rates.py and ledger.py end to end; no sign, bounds or type check on the rate anywhere between fetch_rate and debit',
  }
  assert.deepEqual(missingArgs(declared), [], 'an audited "nothing validates this path" must be dispatchable')
})

// The over-fitting guard, and the test to extend if a real declaration is ever
// wrongly rejected. A declaration is FREE TEXT written by the orchestrator, and
// the rule is only that it name a file — not a length, a word count, or a shape.
test('a declaration naming the files read is accepted, in the shapes one arrives in', () => {
  const real = [
    'read api/orders.py and billing/charge.py; no validation between them',
    'read charge.py, rates.py and ledger.py end to end; no sign, bounds or type check on the rate anywhere between fetch_rate and debit',
    'grepped for Validate( across handlers/*.go and internal/rate.go; nothing on this path',
    'traced fetch_rate through ledger.debit; nothing validates the rate in billing/charge.py',
    'read C:\\src\\app\\billing\\charge.py in full; no check on the amount',
    'read app/models/order.rb and app/controllers/orders_controller.rb; neither bounds the quantity',
    'read charge.py',
  ]
  for (const layersSearched of real) {
    assert.deepEqual(missingArgs({ ...GOOD, layers: [], layersSearched }), [], layersSearched)
  }
})

// The declaration is the whole difference between "confirmed none exist" and a
// forgotten field, so it is read the same way every other null-result field in
// this plugin is: affirmatively, and not satisfied by blank space.
// CHANGED: this used to loop only blank and non-string values, because the rule
// was non-blankness. That was the defect — `n/a`, `none`, `TBD` and `.` are all
// non-blank strings, and each bought the empty-layers path and a TRUE_POSITIVE on
// zero layer agents. `['charge.py']` stays in the table: it stringifies to a
// filename, so only the `typeof` check refuses it.
test('a stand-in does not buy the empty-layers path', () => {
  for (const layersSearched of [
    undefined, null, '', '   ', 0, true, ['charge.py'],
    'n/a', 'N/A', 'none', 'None', 'TBD', 'tbd', '.', '-', 'x', '???', 'unknown', 'nothing found', 'see above',
  ]) {
    const problems = missingArgs({ ...GOOD, layers: [], layersSearched })
    assert.ok(
      problems.some((p) => p.startsWith('layers')),
      `layersSearched ${JSON.stringify(layersSearched)} must not satisfy the declaration`,
    )
  }
})

// CHANGED: the loop was `['', '   ']` and the title said "blank", because that
// branch only fired on a blank string. It now fires on any value that names no
// file read, so a message saying "empty" about `n/a` would be the same lie the
// predicate was.
test('a declaration that names nothing, alongside real layers, is reported rather than ignored', () => {
  for (const layersSearched of ['', '   ', 'n/a', 'TBD']) {
    const problems = missingArgs({ ...GOOD, layersSearched })
    assert.ok(problems.some((p) => p.startsWith('layersSearched')), JSON.stringify(layersSearched))
  }
  assert.deepEqual(missingArgs({ ...GOOD, layersSearched: 'read charge.py' }), [], 'a filled one is simply extra context')
})

test('entirely absent args objects do not throw', () => {
  for (const input of [{}, { finding: null, entryPoint: null }]) {
    const problems = missingArgs(input)
    assert.ok(Array.isArray(problems) && problems.length > 0)
  }
})

// ---------------------------------------------------------- build-poc args

const buildMissing = loadFn(script('triage-poc.js'), 'missingArgs')

const GOOD_BUILD = {
  baseDir: '/plugin/skills/fp-check',
  finding: { summary: 'negative amount reverses a transfer', sink: 'ledger.py:12' },
  verification: {
    status: 'TRUE_POSITIVE',
    impact: {
      impact: 'attacker drains an account',
      rootCause: 'internal',
      classification: 'vulnerability',
    },
    severity: 'High',
    history: { fixed: 'NO', searched: 'git log -p -- ledger.py, issues, CHANGELOG' },
  },
  envelope: { hosts: ['localhost'], level: 1, destructive: false },
  candidates: [{ description: 'direct call', entryPoint: 'transfer_balance', payload: '-500' }],
}

test('triage-poc accepts a well-formed dispatch', () => {
  assert.deepEqual(buildMissing(GOOD_BUILD), [])
})

// These are nested dereferences in the prompt, so a miss THROWS rather than
// interpolating undefined — it would kill the run mid-prompt-construction.
test('triage-poc rejects a missing envelope rather than throwing on .hosts.join()', () => {
  const problems = buildMissing({ ...GOOD_BUILD, envelope: undefined })
  assert.ok(problems.some((p) => p.startsWith('envelope.hosts')))
  assert.ok(problems.includes('envelope.level'))
})

test('triage-poc rejects a non-array hosts list', () => {
  assert.ok(
    buildMissing({ ...GOOD_BUILD, envelope: { ...GOOD_BUILD.envelope, hosts: 'localhost' } })
      .some((p) => p.startsWith('envelope.hosts')),
  )
})

test('triage-poc rejects a missing verification.impact rather than throwing', () => {
  const problems = buildMissing({ ...GOOD_BUILD, verification: {} })
  assert.ok(problems.includes('verification.impact.impact'))
  assert.ok(problems.includes('verification.impact.classification'))
})

test('an absent destructive flag is reported; false is a valid value', () => {
  const { destructive, ...rest } = GOOD_BUILD.envelope
  void destructive
  assert.ok(
    buildMissing({ ...GOOD_BUILD, envelope: rest }).some((p) => p.startsWith('envelope.destructive')),
  )
})

// safety-guidelines.md defines five levels and forbids destructive operations
// above level 2: level 3 is read-only, level 4 is a minimal non-destructive
// probe on a live system, level 5 is nothing without written authorization. The
// builder is told it may not widen the envelope, which does not help when the
// envelope itself authorises what the level forbids.
test('destructive is accepted at levels 1-2 and rejected above them', () => {
  for (const level of [1, 2]) {
    const envelope = { ...GOOD_BUILD.envelope, level, destructive: true }
    assert.deepEqual(buildMissing({ ...GOOD_BUILD, envelope }), [], `level ${level} permits it`)
  }
  for (const level of [3, 4, 5]) {
    const envelope = { ...GOOD_BUILD.envelope, level, destructive: true }
    const problems = buildMissing({ ...GOOD_BUILD, envelope })
    assert.ok(
      problems.some((p) => p.startsWith('envelope.destructive')),
      `destructive at level ${level} must be rejected`,
    )
    assert.match(problems.find((p) => p.startsWith('envelope.destructive')), /safety-guidelines\.md/)
  }
})

test('a non-destructive envelope is fine at every level', () => {
  for (const level of [1, 2, 3, 4, 5]) {
    const envelope = { ...GOOD_BUILD.envelope, level, destructive: false }
    assert.deepEqual(buildMissing({ ...GOOD_BUILD, envelope }), [], `level ${level} must be usable`)
  }
})

test('a level outside 1-5 is rejected rather than passed through', () => {
  // It would reach the builder as "target level: 9", which reads as
  // authoritative and constrains nothing.
  for (const level of [0, 6, 9, -1, 2.5, '3', 'high', true]) {
    const envelope = { ...GOOD_BUILD.envelope, level }
    assert.ok(
      buildMissing({ ...GOOD_BUILD, envelope }).some((p) => p.startsWith('envelope.level')),
      `level ${JSON.stringify(level)} must be rejected`,
    )
  }
})

test('build-poc reports a malformed candidate by index', () => {
  const bad = { ...GOOD_BUILD, candidates: [GOOD_BUILD.candidates[0], { description: 'no payload' }] }
  const problems = buildMissing(bad)
  assert.ok(problems.includes('candidates[1].payload'))
  assert.ok(problems.includes('candidates[1].entryPoint'))
})

test('triage-poc tolerates an empty candidate list at the arg gate', () => {
  assert.deepEqual(buildMissing({ ...GOOD_BUILD, candidates: [] }), [])
})

test('whitespace counts as missing in both validators, not as present', () => {
  for (const [fn, good, path] of [
    [missingArgs, GOOD, 'baseDir'],
    [buildMissing, GOOD_BUILD, 'baseDir'],
  ]) {
    assert.ok(fn({ ...good, [path]: '   ' }).includes(path), `${path} of spaces must be rejected`)
  }
  // triage-static interpolates every one of these into the layer,
  // recovery and threat-model prompts. A blank one reaches an agent as empty space where
  // it expects a fact — the same failure as `undefined`, which is the thing
  // this validator was written for.
  for (const [obj, f] of [
    ['finding', 'summary'],
    ['finding', 'sink'],
    ['finding', 'component'],
    ['finding', 'claimedImpact'],
    ['finding', 'bugClass'],
    ['finding', 'threatModel'],
    ['entryPoint', 'description'],
    ['entryPoint', 'location'],
    ['entryPoint', 'payload'],
  ]) {
    const bad = { ...GOOD, [obj]: { ...GOOD[obj], [f]: '  \t ' } }
    assert.ok(missingArgs(bad).includes(`${obj}.${f}`), `${obj}.${f} of spaces must be rejected`)
  }
  for (const f of ['summary']) {
    assert.ok(buildMissing({ ...GOOD_BUILD, finding: { [f]: '\t\n ' } }).includes(`finding.${f}`))
  }
})

// "Only a TRUE POSITIVE justifies building." SKILL.md says so and left it to
// the orchestrator. triage-static's failing returns carry a fully populated
// `impact` AND a `severity` — NEEDS_MORE_INFO and NOT_EXPLOITABLE both do — so
// forwarding a failure verbatim, which is exactly the instruction for a passing
// one, satisfies every other field and buys a PoC plus a five-agent review for a
// finding that failed its own gates.
test('a forwarded FAILED verification is rejected', () => {
  const failed = {
    reason: 'blocked at ALLOWED_TERM (search.py:20)',
    impact: {
      impact: 'unauthenticated read of arbitrary tables',
      rootCause: 'internal',
      classification: 'vulnerability',
    },
    severity: 'High',
    history: { fixed: 'NO', searched: 'git log -p -- search.py' },
  }
  // Every status that is not TRUE_POSITIVE, including a missing one. The
  // populated `impact`, `severity` and `history` above are what make the bare
  // shape check pass, so they stay on every iteration.
  const statuses = [
    'NOT_EXPLOITABLE',
    'NOT_VULNERABLE',
    'OUT_OF_SCOPE',
    'DISMISSED',
    'FALSE_POSITIVE',
    'ALREADY_FIXED',
    'NEEDS_MORE_INFO',
    'BLOCKED',
    'PROCEED',
    '',
    undefined,
  ]
  for (const status of statuses) {
    const problems = buildMissing({ ...GOOD_BUILD, verification: { ...failed, status } })
    assert.ok(
      problems.some((p) => p.startsWith('verification.status')),
      `status ${JSON.stringify(status)} must not satisfy the shape check`,
    )
  }
})

test('the rejection names the status it received, not just that it was wrong', () => {
  const verification = { ...GOOD_BUILD.verification, status: 'OUT_OF_SCOPE' }
  const problem = buildMissing({ ...GOOD_BUILD, verification }).find((p) =>
    p.startsWith('verification.status'),
  )
  assert.match(problem, /OUT_OF_SCOPE/)
})

test('the validator returns an array and never throws on empty input', () => {
  for (const input of [{}, undefined, { finding: null, verification: null, envelope: null }]) {
    const out = buildMissing(input)
    assert.ok(Array.isArray(out) && out.length > 0)
  }
})


test('a non-array layers list is reported, not thrown on', () => {
  for (const bad of [{ name: 'x' }, 'a string', 7]) {
    const problems = missingArgs({ ...GOOD, layers: bad })
    assert.ok(Array.isArray(problems), 'must return, not throw')
    assert.ok(problems.some((p) => p.startsWith('layers')), `bad shape ${typeof bad} reported`)
  }
})

test('a non-array candidates list is reported, not thrown on', () => {
  // `.entries()` is undefined on an object/string; the throw would escape
  // missingArgs itself and kill the run with no BLOCKED result.
  for (const bad of [{ description: 'x' }, 'a string', 42]) {
    const problems = buildMissing({ ...GOOD_BUILD, candidates: bad })
    assert.ok(Array.isArray(problems), 'must return, not throw')
    assert.ok(problems.some((p) => p.startsWith('candidates')), `bad shape ${typeof bad} reported`)
  }
})

// ==================================================== arg-shape type discipline
//
// `need` used to push only on undefined, null and a blank STRING, so any other
// type cleared it. Below, both directions for each: the shape that failed open
// must now be reported, and the value a real dispatch carries must still pass.

// `missingArgs` calls `auditedSearch` in the two scripts that validate a layers
// declaration, and `loadFns` evaluates the named functions in one scope — so the
// sibling has to be named for those two and must NOT be for the other two, where
// it does not exist and `loadFns` fails loudly.
const validatorFor = (file) =>
  ['triage-static.js', 'triage-batch.js'].includes(file)
    ? loadFns(script(file), 'missingArgs', 'auditedSearch').missingArgs
    : loadFn(script(file), 'missingArgs')

test('a baseDir that is not a string is rejected by all four validators', () => {
  // `[]`, `[null]` and `['']` are the sharp cases: they cleared `need` AND
  // stringified to '' in the shape guard, which skips on a falsy `base`, so the
  // whole validator returned zero problems. `['/plugin/skills/fp-check']`
  // stringifies to a VALID path, so only a type check catches it at all.
  const bad = [[], [null], [''], ['/plugin/skills/fp-check'], {}, 42, true]
  for (const file of ['triage-static.js', 'triage-online.js', 'triage-poc.js', 'triage-batch.js']) {
    const validator = validatorFor(file)
    for (const baseDir of bad) {
      const problems = validator({ baseDir })
      assert.ok(
        problems.some((p) => p.startsWith('baseDir')),
        `${file} accepted baseDir ${JSON.stringify(baseDir)}`,
      )
    }
    assert.ok(
      !validator({ ...GOOD, baseDir: '/plugin/skills/fp-check' }).some((p) => p.startsWith('baseDir')),
      `${file} rejected a well-formed baseDir`,
    )
  }
})

test('a required field that is not a string is rejected, not interpolated', () => {
  // These reached six prompts as the literal text `[object Object]` — the agent
  // LABEL became `layer:[object Object]` — behind a TRUE_POSITIVE verdict.
  for (const field of ['summary', 'sink', 'component', 'claimedImpact', 'bugClass', 'threatModel']) {
    for (const value of [{ cwe: 89 }, ['a', 'b'], 7]) {
      const problems = missingArgs({ ...GOOD, finding: { ...GOOD.finding, [field]: value } })
      assert.ok(problems.some((p) => p.startsWith(`finding.${field}`)), `finding.${field} = ${JSON.stringify(value)}`)
    }
  }
  for (const field of ['description', 'location', 'payload']) {
    for (const value of [{ at: 'x' }, ['a']]) {
      const problems = missingArgs({ ...GOOD, entryPoint: { ...GOOD.entryPoint, [field]: value } })
      assert.ok(problems.some((p) => p.startsWith(`entryPoint.${field}`)), `entryPoint.${field}`)
    }
  }
  assert.deepEqual(missingArgs(GOOD), [], 'a well-formed dispatch must still pass')
})

test('a layer whose name or location is not a string is rejected', () => {
  // The per-item loop was `!layer || !layer.name`, weaker than `need` is for
  // everything else: a truthy non-string cleared it outright.
  for (const field of ['name', 'location']) {
    for (const value of [{ fn: 'validate' }, ['x'], 3]) {
      const layers = [{ ...GOOD.layers[0], [field]: value }]
      const problems = missingArgs({ ...GOOD, layers })
      assert.ok(problems.some((p) => p.startsWith(`layers[0].${field}`)), `layers[0].${field} = ${JSON.stringify(value)}`)
    }
  }
  // A null item still pushes the bare path, unchanged.
  assert.ok(missingArgs({ ...GOOD, layers: [GOOD.layers[0], null] }).includes('layers[1].location'))
})

test('a Windows drive-letter baseDir is accepted, in all four validators', () => {
  // The leading-slash test rejected the only value that works on native Windows,
  // and the message then invited the orchestrator to retry with a POSIX-shaped
  // path that does not exist — so the guard produced the failure it prevents.
  const accepted = [
    'C:/Users/x/.claude/plugins/fp-check/skills/fp-check',
    'C:\\Users\\x\\.claude\\plugins\\fp-check\\skills\\fp-check',
    'd:\\plugins\\fp-check\\skills\\fp-check\\',
    '\\\\server\\share\\plugins\\skills\\fp-check',
  ]
  // "accept a drive letter" must not degrade into "accept anything".
  const refused = ['C:/Users/x/target-repo', 'skills\\fp-check', 'C:/skills/concept-prover', 'skills/fp-check']
  for (const file of ['triage-static.js', 'triage-online.js', 'triage-poc.js', 'triage-batch.js']) {
    const validator = validatorFor(file)
    for (const baseDir of accepted) {
      assert.ok(
        !validator({ baseDir }).some((p) => p.startsWith('baseDir')),
        `${file} rejected the Windows path ${baseDir}`,
      )
    }
    for (const baseDir of refused) {
      assert.ok(validator({ baseDir }).some((p) => p.startsWith('baseDir')), `${file} accepted ${baseDir}`)
    }
  }
})
