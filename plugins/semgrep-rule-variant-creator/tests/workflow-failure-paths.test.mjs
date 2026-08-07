// Failure-path tests: run the real orchestration with stubbed runtime globals.
//
// The other suites check the script's shape. Two real runs checked the happy path. Neither
// reaches what happens when a port goes wrong, because nothing in a real run can be made to
// fail on demand — the validation retry loop in particular had never executed once.
//
// So the script body is evaluated here the way the runtime evaluates it, an async function
// body, with `agent` replaced by a stub that returns scripted results per stage label. That
// makes every failure path deterministic and free.
//
// The caveat worth stating plainly: `pipeline()` below is this file's model of the runtime's
// contract, not the runtime itself. It implements what the Workflow tool documents — each
// item runs through all stages independently, every stage receives
// (prevResult, originalItem, index), and a stage that throws drops that item to null and
// skips its remaining stages. If the real runtime ever diverges from that, these tests agree
// with the wrong model, so they are about the script's logic and never about the platform.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor

// WORKFLOW_SCRIPT lets the pytest wrapper point this suite at a deliberately broken copy and
// assert it goes red. Without that, a suite whose expectations quietly stopped depending on
// the script's behaviour would pass forever.
const scriptPath = process.env.WORKFLOW_SCRIPT
  ? new URL(`file://${process.env.WORKFLOW_SCRIPT}`)
  : new URL('../workflows/port-rule-to-languages.js', import.meta.url)
const source = readFileSync(scriptPath, 'utf8')
const body = source.replace('export const meta', 'const meta', 1)

const VERSION = '1.172.0'
const GREEN = '1/1: ✓ All tests passed'

const RULE = {
  id: 'python-command-injection',
  mode: 'taint',
  sourceLanguage: 'python',
  semgrepVersion: VERSION,
}

// Mirrors the script's naming, `${rule.id}-${slug(canonicalLanguage(semgrepLanguage))}`, with only
// the aliases these scenarios use. If the script's naming moves, the stub's JSON stops matching
// the stem the script looks up and these tests go red rather than quietly agreeing.
const CANONICAL = { golang: 'go', 'c#': 'csharp', 'c++': 'cpp' }

function stemFor(semgrepLanguage) {
  const key = CANONICAL[semgrepLanguage] || semgrepLanguage
  return `${RULE.id}-${key.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`
}

/** `semgrep --test --json` showing this variant's spec graded clean. */
function gradedJson(semgrepLanguage) {
  const stem = stemFor(semgrepLanguage)
  const matches = { [`/out/${stem}/${stem}.src`]: { expected_lines: [3, 7], reported_lines: [3, 7] } }
  return JSON.stringify({
    config_with_errors: [],
    results: { [`${stem}.yaml`]: { checks: { [stem]: { passed: true, matches } } } },
  })
}

/**
 * `semgrep --lang generic --pattern 'ok: <stem>' --json` over a spec with two safe cases.
 *
 * A second run, because `--test --json` has no `ok:` side: it reports the lines the rule matched
 * and the lines it was meant to match, and an annotated safe line is in neither.
 */
function probeJson(semgrepLanguage, lines = [102, 115]) {
  const stem = stemFor(semgrepLanguage)
  return JSON.stringify({
    results: lines.map((line) => ({ start: { line } })),
    errors: [],
    paths: { scanned: [`/out/${stem}/${stem}.src`] },
  })
}

/** Result shapes keyed by the stage label prefix, so a scenario overrides only what it cares about. */
function defaults() {
  return {
    'read-rule': () => RULE,
    assess: (language) => ({
      verdict: 'APPLICABLE',
      reasoning: `${language} has an equivalent sink`,
      semgrepLanguage: language.toLowerCase(),
      semgrepCanAnalyze: true,
      equivalentConstructs: ['os.system -> exec.Command'],
    }),
    refute: () => ({ refuted: false, reasoning: 'the verdict holds' }),
    test: (language) => ({ filePath: `${language}/test`, summary: '2 ruleid, 2 ok' }),
    translate: (language) => ({ filePath: `${language}/rule.yaml`, summary: 'taint rule' }),
    validate: (language) => ({
      testOutput: GREEN,
      testJson: gradedJson(language.toLowerCase()),
      safeCaseJson: probeJson(language.toLowerCase()),
      semgrepVersion: VERSION,
      command: 'semgrep --test --config rule.yaml test',
      iterations: 1,
      summary: 'clean',
    }),
  }
}

/**
 * Execute the workflow body with stubbed globals.
 *
 * Returns the script's return value, the error it threw, and the labels it spawned, so a test
 * can assert on what did *not* run as well as on the result.
 */
async function run({ args, stubs = {} } = {}) {
  const handlers = { ...defaults(), ...stubs }
  const calls = []
  const logs = []
  const prompts = []

  const agent = async (prompt, opts = {}) => {
    const label = opts.label || 'unlabelled'
    calls.push(label)
    prompts.push({ label, prompt, opts })
    const [prefix, language] = label.split(':')
    const handler = handlers[prefix]
    assert.ok(handler, `no stub for stage ${prefix}`)
    return handler(language, calls.filter((c) => c.startsWith(prefix)).length)
  }

  const pipeline = async (items, ...stages) =>
    Promise.all(
      items.map(async (item, index) => {
        let value = item
        for (const stage of stages) {
          try {
            value = await stage(value, item, index)
          } catch {
            return null
          }
        }
        return value
      }),
    )

  const fn = new AsyncFunction('agent', 'pipeline', 'parallel', 'log', 'phase', 'args', 'budget', body)

  try {
    const result = await fn(agent, pipeline, async () => [], (m) => logs.push(m), () => {}, args, {})
    return { result, error: null, calls, logs, prompts }
  } catch (error) {
    return { result: null, error, calls, logs, prompts }
  }
}

const BASE_ARGS = {
  rulePath: '/tmp/rule.yaml',
  languages: ['Go'],
  referencesDir: '/plugin/references',
  outputDir: '/out',
}

test('the happy path returns one passed language and spawns four agents', async () => {
  const { result, error, calls } = await run({ args: BASE_ARGS })
  assert.equal(error, null)
  assert.equal(result.passed.length, 1)
  assert.equal(result.passed[0].validationRounds, 1)
  assert.deepEqual(calls, ['read-rule', 'assess:Go', 'test:Go', 'translate:Go', 'validate:Go'])
})

test('a missing rulePath throws before any agent is spawned', async () => {
  const { error, calls } = await run({ args: { languages: ['Go'] } })
  assert.match(error.message, /needs args\.rulePath/)
  assert.deepEqual(calls, [], 'nothing should be spawned before the args are validated')
})

test('languages given as one phrase throws instead of porting a language by that name', async () => {
  const { error } = await run({ args: { ...BASE_ARGS, languages: 'Go and Java' } })
  assert.match(error.message, /one language per entry/)
  assert.match(error.message, /Go and Java/)
})

test('a stringified array throws rather than becoming a single target', async () => {
  const { error } = await run({ args: { ...BASE_ARGS, languages: '["go","java"]' } })
  assert.match(error.message, /one language per entry/)
})

test('a spelled-out language name is told how to spell it, not that it holds two', async () => {
  // Rejecting these is deliberate — each has a single-token Semgrep key, and that key names the
  // directory — but they are not the "Go and Java" mistake, and the message used to say they
  // were. Someone who typed "Objective C" would go looking for a phrase they never wrote.
  for (const name of ['C Sharp', 'Objective C']) {
    const { error } = await run({ args: { ...BASE_ARGS, languages: [name] } })
    assert.match(error.message, /each a single token/, name)
    assert.match(error.message, /spell a multi-word name the way Semgrep does/, name)
    assert.doesNotMatch(error.message, /hold more than one/, name)
  }
})

test('a dead rule reader stops the run with a named error', async () => {
  const { error, calls } = await run({
    args: BASE_ARGS,
    stubs: { 'read-rule': () => null },
  })
  assert.match(error.message, /did not report back/)
  assert.deepEqual(calls, ['read-rule'], 'no language work should start without the rule')
})

test('an upheld NOT_APPLICABLE yields no directory and spawns no test or translate agent', async () => {
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no shell in this language',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.equal(result.failed.length, 0)
  assert.equal(result.notApplicable.length, 1)
  assert.deepEqual(calls, ['read-rule', 'assess:Go', 'refute:Go'])
})

test('an overturned NOT_APPLICABLE continues to a finished port', async () => {
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no shell',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
      refute: () => ({
        refuted: true,
        reasoning: 'exec.Command reaches a shell',
        equivalentConstructs: ['os.system -> exec.Command'],
        semgrepLanguage: 'go',
      }),
    },
  })

  assert.equal(result.passed.length, 1)
  assert.equal(result.notApplicable.length, 0)
  assert.ok(calls.includes('test:Go'), 'the port should proceed once the verdict is overturned')
})

test('an assessment that never answers the parse question stops rather than proceeding', async () => {
  // The field is schema-required, so an absent one is malformed output rather than permission to
  // proceed. Reading it as permission is the unsafe direction: this gate is what keeps a Pro-only
  // parser out, and it drops a language with no refuter behind it.
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({ verdict: 'APPLICABLE', reasoning: 'ok', semgrepLanguage: 'go' }),
    },
  })

  assert.equal(result.stopped.length, 1)
  assert.match(result.stopped[0].reason, /never said whether semgrep can parse/)
  assert.equal(result.passed.length, 0)
  assert.deepEqual(calls, ['read-rule', 'assess:Go'], 'no port work on an unanswered gate')
})

test('a green over a spec with a single annotated line is not a pass', async () => {
  // testPrompt asks for at least two of each case and test_port_rule_workflow.py holds the golden
  // fixtures to that, so accepting one here would let the live path pass a spec the plugin's own
  // fixture standard rejects — the same split between the two graders this verdict closes.
  const stem = 'python-command-injection-go'
  const thin = JSON.stringify({
    config_with_errors: [],
    results: {
      [`${stem}.yaml`]: {
        checks: {
          [stem]: {
            passed: true,
            matches: { [`/out/${stem}/${stem}.src`]: { expected_lines: [3], reported_lines: [3] } },
          },
        },
      },
    },
  })

  const { result } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        testOutput: GREEN,
        testJson: thin,
        safeCaseJson: probeJson('go'),
        semgrepVersion: VERSION,
        command: 'semgrep --test --config rule.yaml test',
        iterations: 1,
        summary: 'clean',
      }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.match(result.failed[0].reason, /one annotated line/)
})

test('a refuter that renames the language to one semgrep cannot parse reports unsupported', async () => {
  // The parse gate runs before the refuter, against the key the assessment probed. The refuter is
  // allowed to correct that key, so inheriting the old key's answer let a Pro-only parser through
  // the one phase permitted to change the target — reaching translation and three xhigh validation
  // rounds, then landing in `failed` ("fix the rule") when the truth was `unsupported`.
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Elixir'] },
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no raw query sink found',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
      refute: () => ({
        refuted: true,
        reasoning: 'Ecto.Adapters.SQL.query/3 reaches a raw query',
        equivalentConstructs: ['os.system -> Ecto.Adapters.SQL.query'],
        semgrepLanguage: 'elixir',
        semgrepCanAnalyze: false,
        semgrepCheck: 'semgrep --test -> Missing Semgrep extension needed for parsing Elixir target',
      }),
    },
  })

  assert.equal(result.unsupported.length, 1, 'the renamed key is what gets gated')
  assert.equal(result.failed.length, 0, 'this is not a rule to go fix')
  assert.equal(result.passed.length, 0)
  assert.match(result.unsupported[0].semgrepCheck, /Missing Semgrep extension/)
  assert.deepEqual(calls, ['read-rule', 'assess:Elixir', 'refute:Elixir'], 'no port work at all')
})

test('a refuter that renames the language without probing it stops rather than proceeding', async () => {
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Elixir'] },
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no raw query sink found',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
      refute: () => ({
        refuted: true,
        reasoning: 'Ecto raw queries',
        equivalentConstructs: ['os.system -> Ecto.Adapters.SQL.query'],
        semgrepLanguage: 'elixir',
      }),
    },
  })

  assert.equal(result.stopped.length, 1)
  assert.match(result.stopped[0].reason, /without establishing that semgrep can parse it/)
  assert.ok(!calls.includes('test:Elixir'))
})

test('an overturn naming no equivalent constructs leaves the verdict standing', async () => {
  // The prompt requires them and a JSON schema cannot make them conditionally required. This is
  // the one path where the fallback is empty, since the agent being overturned enumerated nothing,
  // so without this the test-first phase writes its spec from an empty construct list.
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no shell in this language',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
      refute: () => ({ refuted: true, reasoning: 'I am fairly sure it ports' }),
    },
  })

  assert.equal(result.notApplicable.length, 1, 'an unevidenced overturn is not an overturn')
  assert.equal(result.passed.length, 0)
  assert.deepEqual(calls, ['read-rule', 'assess:Go', 'refute:Go'])
})

test('an unknown semgrep language stops that language instead of writing a skippable test file', async () => {
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Zig'] },
    stubs: {
      assess: (language) => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: language === 'Zig' ? 'zig' : 'go',
        semgrepCanAnalyze: true,
      }),
    },
  })

  assert.equal(result.passed.length, 1, 'Go still finishes')
  assert.equal(result.passed[0].language, 'Go')
  assert.ok(!calls.includes('test:Zig'), 'no test file is written for a language with no extension')

  // Reported as a refusal carrying its reason, not as `incomplete`. The throw used to drop the
  // item to null, which the caller saw only as "did not report back" — reading as an agent
  // that died and is worth re-running, when it is deterministic and names what to change.
  assert.deepEqual(result.incomplete, [])
  assert.equal(result.stopped.length, 1)
  assert.equal(result.stopped[0].language, 'Zig')
  assert.match(result.stopped[0].reason, /not a Semgrep language key/)
})

test('a target whose test file would be the rule file stops instead of being overwritten', async () => {
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'YAML'] },
    stubs: {
      assess: (language) => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: language === 'YAML' ? 'yaml' : 'go',
        semgrepCanAnalyze: true,
      }),
    },
  })

  assert.equal(result.passed.length, 1, 'Go still finishes')
  assert.equal(result.passed[0].language, 'Go')
  assert.ok(!calls.includes('test:YAML'), 'no spec is written where the rule would overwrite it')
  assert.equal(result.stopped.length, 1)
  assert.match(result.stopped[0].reason, /the same as the rule this directory holds/)
})

test('a dead refuter stops the language instead of silently upholding the verdict', async () => {
  // agent() returns null when a subagent dies on a terminal error after retries. Folding that
  // into "the verdict stands" drops the language on a verdict nothing second-guessed, reported
  // identically to one that was — the single thing the refuter phase exists to prevent.
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no shell in this language',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
      refute: () => null,
    },
  })

  assert.equal(result.notApplicable.length, 0, 'an unchecked verdict is not an upheld verdict')
  assert.equal(result.stopped.length, 1)
  assert.match(result.stopped[0].reason, /never second-guessed/)
  assert.ok(!calls.includes('test:Go'))
})

test('two languages resolving to one directory stop rather than overwrite each other', async () => {
  // pipeline() runs languages concurrently with no barrier, so a shared stem means both write
  // the same rule and test file while each reports its own outcome.
  const { result } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Golang'] },
    stubs: {
      assess: () => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: 'go',
        semgrepCanAnalyze: true,
      }),
    },
  })

  assert.equal(result.passed.length, 1, 'the first claimant finishes')
  assert.equal(result.stopped.length, 1, 'the second stops instead of clobbering it')
  assert.match(result.stopped[0].reason, /same directory/)
})

test('C, C# and C++ get three directories rather than one', async () => {
  // All three are keys semgrep accepts and all three slug to `c`. Accepting the aliases in the
  // extension table reopened the collision the slug comment warns about.
  const key = { C: 'c', 'C#': 'csharp', 'C++': 'cpp' }
  const { result } = await run({
    args: { ...BASE_ARGS, languages: ['C', 'C#', 'C++'] },
    stubs: {
      assess: (language) => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: language === 'C' ? 'c' : language === 'C#' ? 'c#' : 'c++',
        semgrepCanAnalyze: true,
      }),
    },
  })

  assert.equal(result.passed.length, 3, 'no language is stopped as a collision')
  assert.equal(new Set(result.passed.map((r) => r.directory)).size, 3, 'three distinct directories')
  for (const entry of result.passed) {
    assert.ok(entry.directory.endsWith(`-${key[entry.language]}`), entry.directory)
  }
})

test('a whitespace-only language entry is dropped before it costs an agent', async () => {
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Go', '   '] },
  })

  assert.equal(result.passed.length, 1)
  assert.deepEqual(calls, ['read-rule', 'assess:Go', 'test:Go', 'translate:Go', 'validate:Go'])
})

test('languages that are only whitespace name languages as the missing argument', async () => {
  // One message per argument. The combined error opened by naming args.rulePath, so a caller
  // who passed a good rule path and an empty language list was sent to check the wrong one.
  const { error, calls } = await run({ args: { ...BASE_ARGS, languages: ['   '] } })

  assert.match(error.message, /needs args\.languages/)
  assert.doesNotMatch(error.message, /needs args\.rulePath/)
  assert.deepEqual(calls, [])
})

test('validation retries and reports the round it passed on', async () => {
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: (_language, attempt) =>
        attempt < 2
          ? { testOutput: '✗ missed lines: [15]', semgrepVersion: VERSION, iterations: 1, summary: 'pattern too narrow' }
          : { testOutput: GREEN, testJson: gradedJson('go'), safeCaseJson: probeJson('go'), semgrepVersion: VERSION, iterations: 3, summary: 'widened the sink' },
    },
  })

  assert.equal(result.passed.length, 1)
  assert.equal(result.passed[0].validationRounds, 2, 'the retry loop ran a second round')
  assert.equal(calls.filter((c) => c === 'validate:Go').length, 2)
})

test('a rejected round tells the next one the ground the caller refused it on', async () => {
  // Three of the four grounds are ones the agent that ran the round could not see. A round that
  // went genuinely green on the wrong binary reports "clean", so relaying only its own words
  // told the next round "an earlier agent stopped before the tests passed, leaving: clean" — a
  // contradiction with nothing in it to act on, repeated until the retries ran out.
  const { result, prompts } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: (_language, attempt) =>
        attempt < 2
          ? { testOutput: GREEN, semgrepVersion: '1.50.0', iterations: 1, summary: 'clean' }
          : { testOutput: GREEN, testJson: gradedJson('go'), safeCaseJson: probeJson('go'), semgrepVersion: VERSION, iterations: 2, summary: 'reran on the right binary' },
    },
  })

  assert.equal(result.passed.length, 1)
  const rounds = prompts.filter((p) => p.label === 'validate:Go')
  assert.equal(rounds.length, 2, 'the retry round never ran')
  assert.doesNotMatch(rounds[0].prompt, /rejected/, 'the first round has nothing behind it yet')
  assert.match(rounds[1].prompt, /graded with semgrep 1\.50\.0, not the 1\.172\.0/)
  assert.match(rounds[1].prompt, /could not always see/)
})

test('an unreadable semgrep version stops the run instead of burning every retry', async () => {
  // The schema requires the field to be present, not to hold a version, so "unknown" satisfies
  // it. Left to the loop this refuses every round of every language on a condition that cannot
  // change between them — MAX_VALIDATE_ROUNDS xhigh agents each, all for the same reason.
  const { error, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Java'] },
    stubs: { 'read-rule': () => ({ ...RULE, semgrepVersion: 'unknown' }) },
  })

  assert.match(error.message, /No semgrep version could be read/)
  assert.deepEqual(calls, ['read-rule'], 'no language work should start without a baseline')
})

test('validation that never passes stops at the bound and lands in failed', async () => {
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({ testOutput: '✗ missed lines: [15]', iterations: 4, summary: 'still red' }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.equal(result.failed.length, 1)
  assert.equal(result.failed[0].validationRounds, 3, 'bounded by MAX_VALIDATE_ROUNDS')
  assert.equal(calls.filter((c) => c === 'validate:Go').length, 3)
  assert.match(result.failed[0].reason, /still red/)
})

test('a language semgrep cannot analyse is reported apart from NOT_APPLICABLE', async () => {
  // Perl: command injection is if anything worse there than in Python, and semgrep has no
  // Perl frontend. Folding that into NOT_APPLICABLE says the bug class is absent, which is
  // false and sends the reader to the wrong conclusion.
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Perl'] },
    stubs: {
      assess: () => ({
        verdict: 'APPLICABLE_WITH_ADAPTATION',
        reasoning: 'semgrep has no perl frontend; the class exists',
        semgrepLanguage: 'perl',
        semgrepCanAnalyze: false,
        semgrepCheck: 'semgrep --dump-ast -l perl probe.pl -> unsupported language: perl',
      }),
    },
  })

  assert.equal(result.unsupported.length, 1)
  assert.equal(result.unsupported[0].language, 'Perl')
  // This gate drops a language with no refuter behind it, unlike NOT_APPLICABLE. What stands
  // in for the second opinion is that the claim arrives with the command that settled it, so
  // it survives into the result rather than staying in the assessing agent's head.
  assert.match(result.unsupported[0].semgrepCheck, /unsupported language: perl/)
  assert.equal(result.notApplicable.length, 0, 'the vulnerability class is not the reason')
  assert.equal(result.passed.length, 0)
  assert.equal(result.failed.length, 0)
  assert.deepEqual(result.incomplete, [], 'stopping deliberately is not losing an agent')
  assert.deepEqual(calls, ['read-rule', 'assess:Perl'], 'no test, translate, or validate agent')
})

test('an unanalysable language skips the refuter, which could not change the outcome', async () => {
  const { calls } = await run({
    args: { ...BASE_ARGS, languages: ['Perl'] },
    stubs: {
      assess: () => ({
        verdict: 'NOT_APPLICABLE',
        reasoning: 'no perl frontend',
        semgrepLanguage: 'perl',
        semgrepCanAnalyze: false,
      }),
    },
  })

  assert.ok(!calls.includes('refute:Perl'), 'overturning the verdict still yields no rule')
})

test('a pass graded by a different semgrep than the rule was read with is not a pass', async () => {
  // The observed failure. The Elixir parser left OSS semgrep in 1.51.0, so the validate agent
  // installed 1.50.0, ran there, and reported a genuine "All tests passed" for a port that is
  // red on the semgrep it has to run under. Quoting semgrep only binds the agent while the
  // binary is fixed.
  const { result } = await run({
    args: { ...BASE_ARGS, languages: ['Elixir'] },
    stubs: {
      assess: () => ({
        verdict: 'APPLICABLE_WITH_ADAPTATION',
        reasoning: 'ecto raw queries',
        semgrepLanguage: 'elixir',
        semgrepCanAnalyze: true,
      }),
      validate: () => ({
        testOutput: GREEN,
        semgrepVersion: '1.50.0',
        command: 'uv tool run semgrep==1.50.0 --test --config rule.yaml test',
        iterations: 5,
        summary: 'passes under an older semgrep that still ships the Elixir parser',
      }),
    },
  })

  assert.equal(result.passed.length, 0, 'a green from another binary is not a green')
  assert.equal(result.failed.length, 1)
  assert.match(result.failed[0].reason, /graded with semgrep 1\.50\.0, not the 1\.172\.0/)
})

test('a green over a rule semgrep skipped rather than ran is not a pass', async () => {
  const { result } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        testOutput: '1 rule(s) were skipped because they require Pro (try `--pro`)\n1/1: ✓ All tests passed',
        semgrepVersion: VERSION,
        command: 'semgrep --test --config rule.yaml test',
        iterations: 1,
        summary: 'green',
      }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.match(result.failed[0].reason, /skipped the rule rather than running it/)
})

test('a green over a spec that graded no annotation is not a pass', async () => {
  // The third vacuous green, and the one the live path accepted while the golden-fixture grader
  // rejected it. Two routes here: a test agent that writes no `ruleid:` comments, and — because
  // validatePrompt permits fixing a wrong test case — a validate agent three rounds deep deleting
  // the annotation it cannot satisfy. Both leave semgrep printing "All tests passed" over nothing.
  const stem = 'python-command-injection-go'
  const emptyJson = JSON.stringify({
    config_with_errors: [],
    results: {
      [`${stem}.yaml`]: {
        checks: {
          [stem]: {
            passed: true,
            matches: { [`/out/${stem}/${stem}.src`]: { expected_lines: [], reported_lines: [] } },
          },
        },
      },
    },
  })

  const { result } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        testOutput: GREEN,
        testJson: emptyJson,
        safeCaseJson: probeJson('go'),
        semgrepVersion: VERSION,
        command: 'semgrep --test --config rule.yaml test',
        iterations: 1,
        summary: 'clean',
      }),
    },
  })

  assert.equal(result.passed.length, 0, 'semgrep graded nothing, so its green means nothing')
  assert.equal(result.failed.length, 1)
  assert.match(result.failed[0].reason, /no annotated lines/)
})

test('a green over a spec that annotates no safe case is not a pass', async () => {
  // The half of the spec `--test --json` cannot show: it reports the lines the rule matched and
  // the lines it was meant to match, and an annotated safe line is in neither. So a spec with
  // three vulnerable cases and no safe ones grades clean, and the rule that passes it can be
  // broad enough to flag every process launch in the language — the false positive SKILL.md says
  // a port most often invents, and one the golden-fixture grader rejects for the same reason.
  const { result, prompts } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        testOutput: GREEN,
        testJson: gradedJson('go'),
        safeCaseJson: probeJson('go', []),
        semgrepVersion: VERSION,
        command: 'semgrep --test --config rule.yaml test',
        iterations: 1,
        summary: 'clean',
      }),
    },
  })

  assert.equal(result.passed.length, 0, 'a spec with no safe case cannot show the rule is narrow')
  assert.equal(result.failed.length, 1)
  assert.match(result.failed[0].reason, /found 0 `ok: python-command-injection-go` annotation/)

  // The count is semgrep's rather than the agent's, so the run that produces it has to be asked
  // for. Nothing else in the prompt would tell an agent to make it.
  assert.match(
    prompts.find((p) => p.label === 'validate:Go').prompt,
    /--lang generic --pattern 'ok: python-command-injection-go'/,
  )
})

test('a green whose rule id never appears in the graded checks is not a pass', async () => {
  // The rule semgrep never applied: `ruleid:` naming the original rule rather than this variant's
  // stem puts the check under a different key, and the summary line still reads clean.
  const { result } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        testOutput: GREEN,
        testJson: gradedJson('python'),
        safeCaseJson: probeJson('go'),
        semgrepVersion: VERSION,
        command: 'semgrep --test --config rule.yaml test',
        iterations: 1,
        summary: 'clean',
      }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.match(result.failed[0].reason, /graded no check under python-command-injection-go/)
})

test('a self-reported pass with no semgrep output in it is not a pass', async () => {
  // The F2 guard: the verdict is read out of semgrep's words, not the agent's claim.
  const { result } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: () => ({
        passed: true,
        testOutput: 'I fixed the rule and it looks correct now',
        iterations: 1,
        summary: 'claims success',
      }),
    },
  })

  assert.equal(result.passed.length, 0)
  assert.equal(result.failed.length, 1)
})

test('a dead agent mid-pipeline is named in incomplete, not reported as a pass', async () => {
  const { result } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Java'] },
    stubs: { test: (language) => (language === 'Java' ? null : { filePath: 'go/test', summary: '2 ruleid, 2 ok' }) },
  })

  assert.equal(result.passed.length, 1)
  assert.equal(result.failed.length, 0)
  // Named, not counted. Every other outcome carries its language, so a bare `1` here left the
  // caller diffing the requested list against five result sets to find what to re-run.
  assert.deepEqual(result.incomplete, ['Java'])
})

test('one language failing leaves the others unaffected', async () => {
  const { result } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Java'] },
    stubs: {
      assess: (language) => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: language.toLowerCase(),
        semgrepCanAnalyze: true,
      }),
      validate: (language) =>
        language === 'Java'
          ? { testOutput: '✗ incorrect lines: [30]', semgrepVersion: VERSION, iterations: 2, summary: 'too broad' }
          : { testOutput: GREEN, testJson: gradedJson('go'), safeCaseJson: probeJson('go'), semgrepVersion: VERSION, iterations: 1, summary: 'clean' },
    },
  })

  assert.deepEqual(result.passed.map((r) => r.language), ['Go'])
  assert.deepEqual(result.failed.map((r) => r.language), ['Java'])
  assert.deepEqual(result.incomplete, [])
})

// An unpinned agent silently inherits the session's effort. The port still finishes and
// still reports success, just with a different reasoning budget than the phase was designed
// for, so the opts the script passes are the only place the gradient can be observed.
test('every phase pins its own reasoning effort', async () => {
  const { prompts } = await run({ args: BASE_ARGS })
  const effortFor = (label) => prompts.find((p) => p.label === label)?.opts?.effort

  assert.equal(effortFor('read-rule'), 'low', 'reading a YAML file needs no reasoning budget')
  assert.equal(effortFor('assess:Go'), 'high')
  assert.equal(effortFor('translate:Go'), 'xhigh', 'pattern translation is the hardest stage')
  assert.equal(effortFor('validate:Go'), 'xhigh', 'the fix-until-green loop is the hardest stage')

  for (const { label, opts } of prompts) {
    assert.ok(opts?.effort, `${label} pins no effort, so it inherits the session's`)
  }
})

// The script cannot expand {baseDir} and has no filesystem access, so a caller-supplied
// absolute path is the only route by which the reference files reach an agent. Nothing
// downstream fails when that route breaks — the run still reports every language passed —
// so the prompts themselves are the only place it can be observed.
test('the references directory reaches the phase prompts as a resolved path', async () => {
  const ported = await run({ args: BASE_ARGS })
  const promptFor = ({ prompts }, label) => {
    const found = prompts.find((p) => p.label === label)
    assert.ok(found, `${label} never ran, so its prompt was never checked`)
    return found.prompt
  }

  assert.match(promptFor(ported, 'assess:Go'), /\/plugin\/references\/applicability-analysis\.md/)
  assert.match(promptFor(ported, 'translate:Go'), /\/plugin\/references\/language-syntax-guide\.md/)

  // The refuter only runs behind a NOT_APPLICABLE verdict, and it is the phase whose whole
  // job is second-guessing another agent, so it needs the worked examples most.
  const rechecked = await run({
    args: BASE_ARGS,
    stubs: {
      assess: () => ({ verdict: 'NOT_APPLICABLE', reasoning: 'no shell', semgrepLanguage: 'go', semgrepCanAnalyze: true }),
    },
  })
  assert.match(promptFor(rechecked, 'refute:Go'), /\/plugin\/references\/applicability-analysis\.md/)
})

// Required rather than warned about: a run without the references finishes and reports every
// language passed, so a warning is the one signal that can be missed with no consequence.
test('a missing references directory stops the run before any agent is spawned', async () => {
  const { referencesDir, ...withoutReferences } = BASE_ARGS
  assert.ok(referencesDir, 'BASE_ARGS should carry a referencesDir for this to be a real removal')

  const { error, calls } = await run({ args: withoutReferences })

  // The omitted-argument message, not the unresolved-path one below. An empty string is also an
  // unresolvable path, so the shape guard would stop this run too — and telling someone who
  // passed nothing that their path does not resolve sends them looking for a path they never
  // wrote. Asserting which message fires is what keeps the two guards distinguishable.
  assert.match(error.message, /needs args\.referencesDir:/)
  assert.doesNotMatch(error.message, /resolved absolute path/)
  assert.deepEqual(calls, [], 'nothing should be spawned before the guidance is checked')
})

// Non-empty is not the same as resolvable, and the script cannot tell the difference by looking
// — it has no filesystem access. `{baseDir}/references` is the specific value at issue: SKILL.md
// documented it, a script cannot expand it, and the guard above only rejects an empty string, so
// it reached every prompt as a path that does not exist while the run reported clean.
test('an unresolved references path stops the run rather than reading nothing', async () => {
  for (const referencesDir of ['{baseDir}/references', 'references', './references']) {
    const { error, calls } = await run({ args: { ...BASE_ARGS, referencesDir } })

    assert.match(
      error.message,
      /needs args\.referencesDir as a resolved absolute path/,
      `${referencesDir} was accepted`,
    )
    assert.deepEqual(calls, [], `${referencesDir} should stop before an agent is spawned`)
  }
})
