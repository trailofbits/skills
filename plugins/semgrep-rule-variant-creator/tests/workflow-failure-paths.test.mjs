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
    validate: () => ({
      testOutput: GREEN,
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

test('an unknown semgrep language stops that language instead of writing a skippable test file', async () => {
  const { result, calls } = await run({
    args: { ...BASE_ARGS, languages: ['Go', 'Zig'] },
    stubs: {
      assess: (language) => ({
        verdict: 'APPLICABLE',
        reasoning: 'ok',
        semgrepLanguage: language === 'Zig' ? 'zig' : 'go',
      }),
    },
  })

  assert.equal(result.passed.length, 1, 'Go still finishes')
  assert.equal(result.passed[0].language, 'Go')
  assert.equal(result.incomplete, 1, 'Zig is reported, not silently dropped')
  assert.ok(!calls.includes('test:Zig'), 'no test file is written for a language with no extension')
})

test('validation retries and reports the round it passed on', async () => {
  const { result, calls } = await run({
    args: BASE_ARGS,
    stubs: {
      validate: (_language, attempt) =>
        attempt < 2
          ? { testOutput: '✗ missed lines: [15]', semgrepVersion: VERSION, iterations: 1, summary: 'pattern too narrow' }
          : { testOutput: GREEN, semgrepVersion: VERSION, iterations: 3, summary: 'widened the sink' },
    },
  })

  assert.equal(result.passed.length, 1)
  assert.equal(result.passed[0].validationRounds, 2, 'the retry loop ran a second round')
  assert.equal(calls.filter((c) => c === 'validate:Go').length, 2)
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
  assert.equal(result.incomplete, 0, 'stopping deliberately is not the same as losing an agent')
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

test('a dead agent mid-pipeline is counted as incomplete, not as a pass', async () => {
  const { result } = await run({
    args: BASE_ARGS,
    stubs: { test: () => null },
  })

  assert.equal(result.passed.length, 0)
  assert.equal(result.failed.length, 0)
  assert.equal(result.incomplete, 1)
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
          : { testOutput: GREEN, semgrepVersion: VERSION, iterations: 1, summary: 'clean' },
    },
  })

  assert.deepEqual(result.passed.map((r) => r.language), ['Go'])
  assert.deepEqual(result.failed.map((r) => r.language), ['Java'])
  assert.equal(result.incomplete, 0)
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
      assess: () => ({ verdict: 'NOT_APPLICABLE', reasoning: 'no shell', semgrepLanguage: 'go' }),
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

  assert.match(error.message, /needs args\.referencesDir/)
  assert.deepEqual(calls, [], 'nothing should be spawned before the guidance is checked')
})
