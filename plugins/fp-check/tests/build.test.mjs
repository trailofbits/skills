import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, script } from './extract.mjs'

const BUILD = script('triage-poc.js')
const selectAttempts = loadFn(BUILD, 'selectAttempts')
const isAcceptableBuild = loadFn(BUILD, 'isAcceptableBuild')

const candidate = (n) => ({ name: `path-${n}`, description: `d${n}` })
const goodBuild = {
  built: true,
  executed: true,
  lintPassed: true,
  pocType: 'test-integrated',
  path: 'tests/test_vuln.py',
  absolutePath: '/tmp/wf-worktree-3/tests/test_vuln.py',
  command: 'pytest tests/test_vuln.py',
  output: 'AssertionError: alice went negative (-400)',
  invokedSymbol: 'target_app.ledger.transfer_balance',
}

// --------------------------------------------------------- selectAttempts

test('caps at the maximum and reports what was held back', () => {
  const { chosen, heldBack } = selectAttempts([1, 2, 3, 4, 5].map(candidate), 2)
  assert.equal(chosen.length, 2)
  assert.equal(heldBack, 3, 'held-back count must be reported, never silently dropped')
})

test('an empty candidate list yields zero attempts and does not throw', () => {
  const { chosen, heldBack } = selectAttempts([], 2)
  assert.equal(chosen.length, 0)
  assert.equal(heldBack, 0)
})

test('a missing candidate list yields zero attempts and does not throw', () => {
  for (const bad of [undefined, null]) {
    const { chosen, heldBack } = selectAttempts(bad, 2)
    assert.equal(chosen.length, 0)
    assert.equal(heldBack, 0)
  }
})

test('fewer candidates than the cap holds nothing back', () => {
  const { chosen, heldBack } = selectAttempts([candidate(1)], 2)
  assert.equal(chosen.length, 1)
  assert.equal(heldBack, 0)
})

test('the retry loop is bounded — attempts never exceed the cap', () => {
  // The build loop iterates over exactly `chosen`, so bounding chosen bounds the
  // loop. A large candidate list must not produce a long retry chain.
  const many = Array.from({ length: 500 }, (_, i) => candidate(i))
  assert.equal(selectAttempts(many, 2).chosen.length, 2)
})

// ------------------------------------------------------ isAcceptableBuild

test('a complete build is accepted', () => {
  assert.equal(isAcceptableBuild(goodBuild), true)
})

test('a dead builder agent yields null and is rejected, not thrown on', () => {
  assert.equal(isAcceptableBuild(null), false)
  assert.equal(isAcceptableBuild(undefined), false)
})

// Each field is gated for a concrete downstream reason: command and output are
// what review-poc interpolates, invokedSymbol is the only evidence for
// Principle 5, and absolutePath is what makes the artifact readable at all —
// the builder runs with isolation: 'worktree', so a repo-relative path resolves
// to nothing for the five challenge agents, for the report that cites it, or
// for the user who has to run it. Missing any one means review-poc returns
// BLOCKED after Phase 4 has already been paid for.
//
// `path` and `pocType` are here because that is exactly what happened to them:
// review-poc requires both, this gate did not, and whitespace in either
// returned BUILT and then BLOCKED with no reviewer having run.
//
// Each is checked in all three falsy shapes a model can actually produce —
// reported false, omitted entirely, returned as an empty string — because
// nothing in the schema distinguishes them.
test('every gate condition is load-bearing, in each shape a model can produce', () => {
  for (const field of [
    'built',
    'executed',
    'lintPassed',
    'absolutePath',
    'path',
    'pocType',
    'command',
    'output',
    'invokedSymbol',
  ]) {
    const omitted = { ...goodBuild }
    delete omitted[field]
    assert.equal(isAcceptableBuild({ ...goodBuild, [field]: false }), false, `${field}=false`)
    assert.equal(isAcceptableBuild(omitted), false, `${field} omitted`)
    assert.equal(isAcceptableBuild({ ...goodBuild, [field]: '' }), false, `${field}=''`)
  }
})

// The fourth shape, and the one bare truthiness let through. JSON Schema
// `required` checks presence and not content, so `output: '   '` is
// schema-valid: a builder reporting whitespace for every string field returned
// BUILT, and that whitespace reached all five challenge prompts as the
// "Captured output" the reviewers are supposed to judge, plus review-poc's lint
// command as `--symbol '  '`.
test('whitespace is not content: the string fields are trimmed before gating', () => {
  for (const field of ['absolutePath', 'command', 'output', 'invokedSymbol']) {
    for (const blank of [' ', '   ', '\t', '\n', ' \t\n ']) {
      assert.equal(
        isAcceptableBuild({ ...goodBuild, [field]: blank }),
        false,
        `${field}=${JSON.stringify(blank)} must not pass the gate`,
      )
    }
  }
})

test('a build whose only whitespace is INSIDE a real value is still accepted', () => {
  // The trim must not reject legitimate values that merely contain spaces —
  // `command` and `output` almost always do.
  assert.equal(
    isAcceptableBuild({
      ...goodBuild,
      command: 'pytest -k "transfer negative" tests/test_vuln.py',
      output: '\nAssertionError: alice went negative (-400)\n',
    }),
    true,
  )
})

test('a non-string in a string field is rejected rather than passed on truthiness', () => {
  // The gate feeds these straight into prompts. A number or an object would
  // interpolate as "42" or "[object Object]" and read as authoritative.
  for (const field of ['absolutePath', 'command', 'output', 'invokedSymbol']) {
    for (const wrong of [42, true, { path: 'x' }, ['x']]) {
      assert.equal(isAcceptableBuild({ ...goodBuild, [field]: wrong }), false, `${field}=${typeof wrong}`)
    }
  }
})

test('missing fields are rejected rather than treated as true', () => {
  assert.equal(isAcceptableBuild({ built: true }), false)
  assert.equal(isAcceptableBuild({}), false)
})

test('always returns a boolean, never a truthy object', () => {
  for (const input of [null, {}, goodBuild, { built: 1, executed: 1, lintPassed: 1 }]) {
    assert.equal(typeof isAcceptableBuild(input), 'boolean')
  }
})

// The same by-exclusion read one stage earlier, and the same premise behind it:
// `type` is advisory, so a builder can answer `built: 'no'` inside the schema.
// Truthiness read every one of these as YES, so a build the builder itself said
// did not happen bought five reviewers and reached REPORTED.
test('an off-type build boolean fails the gate rather than passing it', () => {
  for (const field of ['built', 'executed', 'lintPassed']) {
    for (const value of ['no', 'false', 'FAILED', 1, {}, []]) {
      assert.equal(
        isAcceptableBuild({ ...goodBuild, [field]: value }),
        false,
        `${field} = ${JSON.stringify(value)} must not clear the build gate`,
      )
    }
  }
  assert.equal(isAcceptableBuild(goodBuild), true, 'a real build must still pass')
})
