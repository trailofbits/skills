// Unit tests for the deterministic JavaScript in the workflow script.
//
// The script cannot be imported: the runtime wraps its body in an async function and
// supplies the top-level `return`, so `import` rejects it. Each function under test is
// therefore extracted from the source text and evaluated on its own. A rename or deletion
// makes extraction throw rather than silently test nothing.
//
// Run directly with `node --test tests/`, or through the pytest wrapper in
// test_workflow_contract.py so `make check` picks it up.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../workflows/port-rule-to-languages.js', import.meta.url), 'utf8')

/**
 * Return the full text of a named top-level function from the workflow script.
 *
 * Brace-matches from the signature, which is sound for these functions because none of
 * them contain a brace inside a string or regex literal.
 */
function blockFrom(start, what) {
  let depth = 0
  for (let i = source.indexOf('{', start); i < source.length; i += 1) {
    if (source[i] === '{') depth += 1
    else if (source[i] === '}') {
      depth -= 1
      if (depth === 0) return source.slice(start, i + 1)
    }
  }
  throw new Error(`unbalanced braces in ${what}`)
}

function extract(name) {
  const start = source.indexOf(`function ${name}(`)
  assert.notStrictEqual(start, -1, `no function ${name}() in the workflow script`)
  return blockFrom(start, `${name}()`)
}

function extractTable(name) {
  const start = source.indexOf(`const ${name} = {`)
  assert.notStrictEqual(start, -1, `no const ${name} in the workflow script`)
  return blockFrom(start, name)
}

/** Return the text of a single-line `const NAME = ...` declaration. */
function extractLineConst(name) {
  const start = source.indexOf(`const ${name} = `)
  assert.notStrictEqual(start, -1, `no const ${name} in the workflow script`)
  return source.slice(start, source.indexOf('\n', start))
}

function load(name, ...preamble) {
  return new Function(`${preamble.join('\n')}\n${extract(name)}\nreturn ${name}`)()
}

const VALIDATION_DEPS = [
  extractLineConst('SKIPPED_RATHER_THAN_RUN'),
  extract('semgrepVersion'),
]

const slug = load('slug')
const canonicalLanguage = load('canonicalLanguage', extractTable('CANONICAL_BY_LANGUAGE'))
const partition = load('partition')
const validationFailure = load('validationFailure', ...VALIDATION_DEPS)
const validationPassed = load('validationPassed', ...VALIDATION_DEPS, extract('validationFailure'))
const testFileExtension = load('testFileExtension', extractTable('EXTENSION_BY_LANGUAGE'))

// The semgrep the rule was read with. A port is only green when the same one graded it.
const VERSION = '1.172.0'
const GREEN = '1/1: ✓ All tests passed'

test('extraction fails loudly when a function is gone', () => {
  assert.throws(() => load('noSuchFunction'), /no function noSuchFunction/)
})

test('slug flattens a language name to a directory-safe stem', () => {
  assert.equal(slug('Go'), 'go')
  assert.equal(slug('TypeScript'), 'typescript')
  assert.equal(slug('C Sharp'), 'c-sharp')
  assert.equal(slug('  Go  '), 'go')
})

test('slug collapses punctuation-bearing names, which is why callers pass semgrep keys', () => {
  // The reason `stem` slugs assessment.semgrepLanguage first: these three targets are
  // distinct languages that all slug to the same directory.
  assert.equal(slug('C#'), 'c')
  assert.equal(slug('C++'), 'c')
  assert.equal(slug('C'), 'c')
  assert.equal(slug('C#'), slug('C'))

  // Semgrep's own keys are already flat identifiers, so they survive slugging intact.
  assert.equal(slug('csharp'), 'csharp')
  assert.equal(slug('cpp'), 'cpp')
})

test('testFileExtension derives from semgrep language key, ignoring what the agent claimed', () => {
  assert.equal(testFileExtension('Rust', { semgrepLanguage: 'rust' }), 'rs')
  assert.equal(testFileExtension('Solidity', { semgrepLanguage: 'solidity' }), 'sol')
  assert.equal(testFileExtension('C#', { semgrepLanguage: 'csharp' }), 'cs')
  assert.equal(testFileExtension('Go', { semgrepLanguage: ' GO ' }), 'go')

  // The table wins. An agent's `.txt` would produce a file semgrep skips entirely.
  assert.equal(testFileExtension('Go', { semgrepLanguage: 'go', fileExtension: 'txt' }), 'go')
})

test('canonicalLanguage keeps aliases out of one directory', () => {
  // slug() flattens punctuation, so `c#` and `c++` both reduce to `c` — which is also C. The
  // extension table accepts all three as keys, so without canonicalising first, three targets
  // name one directory and overwrite each other while all three report a pass.
  assert.notEqual(slug(canonicalLanguage('c#')), slug(canonicalLanguage('c')))
  assert.notEqual(slug(canonicalLanguage('c++')), slug(canonicalLanguage('c')))
  assert.notEqual(slug(canonicalLanguage('c#')), slug(canonicalLanguage('c++')))
  assert.equal(new Set(['c', 'c#', 'c++'].map((k) => slug(canonicalLanguage(k)))).size, 3)

  // Aliases of one language collapse deliberately, so the collision guard can see them.
  for (const [alias, canonical] of Object.entries({
    golang: 'go',
    py: 'python',
    python3: 'python',
    sol: 'solidity',
    kt: 'kotlin',
    ex: 'elixir',
    tf: 'terraform',
    hcl: 'terraform',
    docker: 'dockerfile',
    ' SOL ': 'solidity',
  })) {
    assert.equal(canonicalLanguage(alias), canonical, `alias ${alias}`)
  }

  // Anything not an alias passes through, so an unknown key still reaches the extension guard.
  assert.equal(canonicalLanguage('rust'), 'rust')
  assert.equal(canonicalLanguage('zig'), 'zig')
  assert.equal(canonicalLanguage(''), '')
})

test('testFileExtension knows the aliases semgrep accepts, not just canonical names', () => {
  // An assessment reports whichever spelling it read, and all of these are real semgrep keys.
  // A table holding only `solidity` and `python` rejects half the correct answers, stopping
  // ports that were never wrong.
  const aliases = { sol: 'sol', py: 'py', kt: 'kt', ex: 'ex', tf: 'tf', golang: 'go', docker: 'dockerfile' }
  for (const [key, expected] of Object.entries(aliases)) {
    assert.equal(testFileExtension('x', { semgrepLanguage: key }), expected, `alias ${key}`)
  }
})

test('testFileExtension throws rather than guessing, even when the agent claims one', () => {
  // The F1 failure: an extension semgrep does not associate with the rule's language makes it
  // skip the file, grade nothing, and report "All tests passed" with exit 0. Verified against
  // semgrep 1.172.0 — a `languages: [python]` rule beside a `.zig` file prints `1/1: ✓ All
  // tests passed` and exits 0.
  assert.throws(() => testFileExtension('Zig', { semgrepLanguage: 'zig' }), /not a Semgrep language key/)
  assert.throws(() => testFileExtension('Zig', {}), /not a Semgrep language key/)

  // The claimed extension is no longer an escape hatch. It used to be, and because the prompt
  // asked every assessment for one, the throw above almost never fired: Perl reached the test
  // writer with `.pl`, a file semgrep cannot read and therefore silently passes.
  assert.throws(
    () => testFileExtension('Perl', { semgrepLanguage: 'perl', fileExtension: 'pl' }),
    /not a Semgrep language key/,
  )
})

test('testFileExtension rejects a key that only resolves on the prototype chain', () => {
  // Both are strings an assessment can report, and a truthiness test on a plain object literal
  // finds something for each.
  assert.throws(() => testFileExtension('x', { semgrepLanguage: 'constructor' }), /not a Semgrep/)
  assert.throws(() => testFileExtension('x', { semgrepLanguage: '__proto__' }), /not a Semgrep/)
})

test('testFileExtension truncates a prose language key instead of echoing a paragraph', () => {
  // Verbatim from a real run, where the assessment used the field for an explanation.
  const prose = 'n/a — Perl has no Semgrep language key (nearest fallback is `generic`, which cannot run taint mode)'
  assert.throws(() => testFileExtension('Perl', { semgrepLanguage: prose }), (error) => {
    assert.match(error.message, /…/, 'a 100-character key should be elided')
    assert.ok(error.message.length < 320, `error is ${error.message.length} characters`)
    return true
  })
})

test('validationPassed reads semgrep output rather than a self-reported boolean', () => {
  const at = (testOutput) => ({ testOutput, semgrepVersion: VERSION })
  assert.equal(validationPassed(at(GREEN), VERSION), true)
  assert.equal(validationPassed(at('✗ python-command-injection-go\n missed lines: [15]'), VERSION), false)
  assert.equal(validationPassed({ testOutput: '', passed: true, semgrepVersion: VERSION }, VERSION), false, 'a claimed pass is not a pass')
  assert.equal(validationPassed({}, VERSION), false)
  assert.equal(validationPassed(null, VERSION), false)
})

test('validationPassed rejects a pass graded by a different semgrep', () => {
  // The observed failure: an agent that could not make its Elixir tests pass installed semgrep
  // 1.50.0, the last OSS build shipping the Elixir parser, and reported its genuine green.
  // The words were semgrep's; the binary was not the one the rule has to run under.
  assert.equal(validationPassed({ testOutput: GREEN, semgrepVersion: '1.50.0' }, VERSION), false)
  assert.match(
    validationFailure({ testOutput: GREEN, semgrepVersion: '1.50.0' }, VERSION),
    /graded with semgrep 1\.50\.0, not the 1\.172\.0/,
  )

  // Tolerant of how the version is reported, strict about which one it is.
  assert.equal(validationPassed({ testOutput: GREEN, semgrepVersion: 'semgrep 1.172.0' }, VERSION), true)
})

test('validationPassed fails when it cannot tell which semgrep spoke', () => {
  // A check that cannot identify the binary has not checked anything, so silence is a failure.
  assert.equal(validationPassed({ testOutput: GREEN }, VERSION), false)
  assert.equal(validationPassed({ testOutput: GREEN, semgrepVersion: VERSION }, ''), false)
  assert.match(validationFailure({ testOutput: GREEN, semgrepVersion: VERSION }, ''), /no baseline/)
})

test('validationPassed rejects a green from a rule semgrep skipped rather than ran', () => {
  // Semgrep reports "All tests passed" over zero graded tests when it skips the rule, and a
  // Pro-only parser is the common way to get there.
  const skipped = [
    'Missing Semgrep extension needed for parsing Elixir target. Try adding `--pro-languages`',
    '1 rule(s) were skipped because they require Pro (try `--pro`)\n1/1: ✓ All tests passed',
  ]
  for (const testOutput of skipped) {
    assert.equal(validationPassed({ testOutput, semgrepVersion: VERSION }, VERSION), false, testOutput)
  }

  // Noise that must NOT fail a green port. All of it can appear in the last 20 lines an agent
  // reports verbatim, so a loose pattern here fails a good rule through all three retries —
  // and unlike a missed phrasing, that has no fallback behind it.
  const green = [
    `${GREEN}\nRules skipped: 0`,
    `${GREEN}\n2 files were skipped because they matched .semgrepignore`,
    `${GREEN}\nUpgrade to Semgrep Pro for interfile analysis: try --pro`,
    `${GREEN}\nPartially analyzed due to parsing or internal Semgrep errors: 1 file`,
  ]
  for (const testOutput of green) {
    assert.equal(
      validationPassed({ testOutput, semgrepVersion: VERSION }, VERSION),
      true,
      testOutput,
    )
  }
  assert.match(
    validationFailure({ testOutput: skipped[1], semgrepVersion: VERSION }, VERSION),
    /skipped the rule rather than running it/,
  )
})

const ported = (language, passed) => ({ language, validation: { passed }, rounds: 1 })
const dropped = (language) => ({ language, skipped: true })
const untooled = (language) => ({ language, unsupported: true })

test('partition filters nulls before reading any field', () => {
  const result = partition([null, ported('go', true), null], 3)
  assert.equal(result.passed.length, 1)
  assert.equal(result.failed.length, 0)
  assert.equal(result.lost, 2, 'a dropped item is counted, not forgotten')
})

test('partition counts a language whose validation never reported as failed', () => {
  const result = partition([{ language: 'go', validation: null }], 1)
  assert.equal(result.failed.length, 1)
  assert.equal(result.passed.length, 0)
  assert.equal(result.lost, 0)
})

test('partition never counts a skipped language as failed', () => {
  const result = partition([dropped('solidity'), ported('go', true)], 2)
  assert.equal(result.skipped.length, 1)
  assert.equal(result.failed.length, 0, 'NOT_APPLICABLE is not a failure')
  assert.equal(result.passed.length, 1)
})

test('partition never counts a language semgrep cannot analyse as failed', () => {
  // A language with no semgrep parser was never ported, so it is neither a pass nor a failure
  // to fix. Counting it as failed would send someone to debug a rule that does not exist.
  const result = partition([untooled('perl'), ported('go', true)], 2)
  assert.equal(result.unsupported.length, 1)
  assert.equal(result.failed.length, 0)
  assert.equal(result.skipped.length, 0, 'unsupported is not the same bucket as NOT_APPLICABLE')
  assert.equal(result.passed.length, 1)
})

test('partition on empty input yields empty sets and does not throw', () => {
  const result = partition([], 0)
  assert.deepEqual(
    {
      passed: result.passed,
      failed: result.failed,
      skipped: result.skipped,
      unsupported: result.unsupported,
      lost: result.lost,
    },
    { passed: [], failed: [], skipped: [], unsupported: [], lost: 0 },
  )
})

test('partition separates passed from failed on the validation verdict alone', () => {
  const result = partition([ported('go', true), ported('java', false)], 2)
  assert.deepEqual(result.passed.map((r) => r.language), ['go'])
  assert.deepEqual(result.failed.map((r) => r.language), ['java'])
})
