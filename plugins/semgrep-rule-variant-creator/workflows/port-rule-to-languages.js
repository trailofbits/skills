export const meta = {
  name: 'port-rule-to-languages',
  description: 'Port an existing Semgrep rule to one or more target languages, test-first',
  whenToUse:
    'Use when porting an existing Semgrep rule to other languages. Args: rulePath, the path to the rule YAML; languages, an array with one target language per entry; referencesDir, an absolute path to a directory holding applicability-analysis.md and language-syntax-guide.md; and optionally outputDir, which defaults to the working directory. Each language gets its own applicability analysis, test file, translated rule, and validation run, and lands in its own <rule-id>-<language>/ directory.',
  phases: [
    { title: 'Read rule', detail: 'extract id, mode, sources, sinks, sanitizers' },
    { title: 'Assess applicability', detail: 'one agent per target language' },
    { title: 'Recheck applicability', detail: 'refute NOT_APPLICABLE before dropping a language' },
    { title: 'Write tests', detail: 'test-first, before any rule exists' },
    { title: 'Translate rule', detail: 'AST-guided pattern translation' },
    { title: 'Validate', detail: 'semgrep --test, retried until it passes' },
  ],
}

// Phase order is the point of this script: encoded here, test-first cannot be skipped
// and a language cannot be half-ported.
//
// pipeline() rather than sequential languages, because the ordering constraint is per
// language — a rule is never written before its tests, and never left unvalidated —
// while Go can still reach translation with Java still being assessed. A barrier
// between stages would batch every language into each phase and buy nothing.
//
// Two decisions in a port have no oracle behind them, so the script holds them rather
// than a single agent's judgment. A NOT_APPLICABLE verdict suppresses all the work for
// that language and nothing downstream would ever contradict it, so it gets an
// independent refuter. And an agent told to iterate until the tests pass can stop
// early, so the retry lives in the loop below instead of in its prompt.

const MAX_VALIDATE_ROUNDS = 3

// 4 agents when a language ports cleanly: assess, test, translate, validate. A refuted
// NOT_APPLICABLE verdict adds one, and each validation retry after the first adds one.
const MAX_AGENTS_PER_LANGUAGE = 4 + 1 + (MAX_VALIDATE_ROUNDS - 1)

// Deliberately no field carrying the file's content. Asked to repeat the rule back verbatim,
// the reader HTML-escaped `<` and `>`, silently breaking Semgrep's `<... ...>` deep-expression
// operator in every prompt downstream and leaving four agents reasoning about sanitizer
// clauses that would not parse. Each phase gets args.rulePath and reads the file itself.
const RULE_SCHEMA = {
  type: 'object',
  required: ['id', 'semgrepVersion'],
  properties: {
    id: { type: 'string', description: 'The rule id, verbatim' },
    mode: { type: 'string', description: 'taint, or empty when the rule is pattern-based' },
    sourceLanguage: { type: 'string', description: "The rule's current languages: key" },
    sources: { type: 'array', items: { type: 'string' } },
    sinks: { type: 'array', items: { type: 'string' } },
    sanitizers: { type: 'array', items: { type: 'string' } },
    semgrepVersion: {
      type: 'string',
      description: 'What `semgrep --version` prints, verbatim, from the semgrep on PATH',
    },
  },
}

const APPLICABILITY_SCHEMA = {
  type: 'object',
  required: ['verdict', 'reasoning', 'semgrepLanguage', 'semgrepCanAnalyze'],
  properties: {
    verdict: {
      type: 'string',
      enum: ['APPLICABLE', 'APPLICABLE_WITH_ADAPTATION', 'NOT_APPLICABLE'],
    },
    reasoning: { type: 'string' },
    semgrepLanguage: {
      type: 'string',
      description:
        "Semgrep's own language key, exactly as `semgrep show supported-languages` prints it, e.g. go, java, ts, csharp. A key, never prose",
    },
    // Separate from the verdict because they answer different questions, and conflating them
    // is what let a Pro-only parser through: the class can exist in a language Semgrep cannot
    // read, and a rule for it is ungradeable however applicable the pattern is.
    semgrepCanAnalyze: {
      type: 'boolean',
      description:
        'False when the installed semgrep cannot parse this language, Pro-gated parsers included. Establish it by running semgrep, not from memory',
    },
    // A false here drops the language with no second opinion, the same standing a
    // NOT_APPLICABLE verdict has — and that one earns a refuter. This claim does not, because
    // it is settled by a command rather than by judgment, and a refuter would only re-run it.
    // What it earns instead is the treatment validation gets: quote the tool, do not assert.
    semgrepCheck: {
      type: 'string',
      description:
        'The semgrep command you ran to settle semgrepCanAnalyze and the line it printed, so the claim can be rechecked in one step',
    },
    equivalentConstructs: {
      type: 'array',
      description: 'Original construct -> target-language equivalent, one per entry',
      items: { type: 'string' },
    },
  },
}

const REFUTATION_SCHEMA = {
  type: 'object',
  required: ['refuted', 'reasoning'],
  properties: {
    refuted: {
      type: 'boolean',
      description: 'True only when the NOT_APPLICABLE verdict is wrong and the rule does port',
    },
    reasoning: { type: 'string' },
    equivalentConstructs: {
      type: 'array',
      description: 'Original construct -> target-language equivalent, required when refuting',
      items: { type: 'string' },
    },
    semgrepLanguage: {
      type: 'string',
      description: "Semgrep's own language key, when refuting a verdict that named the wrong one",
    },
    // A corrected key is a key nothing has probed: the parse gate runs before this phase, against
    // the key the assessment reported. So a refutation that renames the target has to answer for
    // it, on the same terms the assessment does — by running semgrep, not from memory.
    semgrepCanAnalyze: {
      type: 'boolean',
      description:
        'Required when you name a different semgrepLanguage: whether the installed semgrep can parse that key, Pro-gated parsers included. Establish it by running semgrep',
    },
    semgrepCheck: {
      type: 'string',
      description: 'The command that settled semgrepCanAnalyze and the line it printed',
    },
  },
}

const ARTIFACT_SCHEMA = {
  type: 'object',
  required: ['filePath', 'summary'],
  properties: {
    filePath: { type: 'string' },
    summary: { type: 'string', description: 'One sentence' },
  },
}

// No `passed` field: the agent that just edited the rule is not the judge of whether it
// passes. It reports semgrep's own output and the script reads the verdict out of it.
//
// The version and command are reported for the same reason the boolean is not. Reading the
// verdict out of semgrep's words only binds the agent while it is the same semgrep: one that
// could not make the tests pass produced "All tests passed" by installing an older build whose
// parser for the target language was not yet Pro-gated. The words were semgrep's; the binary
// was not the one the rule has to run under.
const VALIDATION_SCHEMA = {
  type: 'object',
  required: [
    'testOutput',
    'testJson',
    'safeCaseJson',
    'semgrepVersion',
    'command',
    'iterations',
    'summary',
  ],
  properties: {
    testOutput: {
      type: 'string',
      description: 'The final semgrep --test run output, verbatim, last 20 lines or fewer',
    },
    // Required, because "All tests passed" is also what semgrep prints over a spec with nothing
    // annotated. Carried as the tool's own text rather than a shape the agent fills in, for the
    // reason `passed` is absent: the agent reports what semgrep said, the script reads the verdict.
    testJson: {
      type: 'string',
      description:
        'The complete stdout of `semgrep --test --json --config <rule> <test>`, verbatim and unedited',
    },
    // Required for the reason `passed` is absent: `--test --json` says nothing about the lines the
    // rule must leave alone, so this is semgrep counting that half rather than the agent stating it.
    safeCaseJson: {
      type: 'string',
      description:
        "The complete stdout of `semgrep --lang generic --pattern 'ok: <rule id>' --json <test>`, verbatim and unedited",
    },
    semgrepVersion: {
      type: 'string',
      description: 'What `semgrep --version` prints for the binary that produced testOutput',
    },
    command: { type: 'string', description: 'The exact semgrep --test command line you ran' },
    iterations: { type: 'number' },
    summary: { type: 'string', description: 'One sentence: what failed and what fixed it' },
  },
}

const SCOPE = `Deliver exactly this phase's artifact at the scope described. Make routine judgment calls yourself. If the rule or target looks mistaken, say so in one sentence and continue as asked.`

// An absolute path, resolved by the caller: a workflow script cannot expand {baseDir}, and
// the reference files do not sit in the user's project. Required rather than optional,
// because nothing downstream fails without it — the port just gets made without the
// guidance it depends on, and every language still reports as passed.
const referencesDir =
  typeof args?.referencesDir === 'string' ? args.referencesDir.replace(/\/+$/, '') : ''

function reference(file, what) {
  return `Read ${referencesDir}/${file} — it ${what}.\n\n`
}

// Slugged from Semgrep's own language key when the assessment supplies one, because the
// user's word for a language does not survive slugging: "C#" and "C++" both reduce to "c",
// which is also C, so three targets would fight over one directory. Semgrep's keys are
// already flat identifiers, and using them keeps the rule id and its languages: key
// agreeing on what the target is.
function slug(language) {
  return language
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

// Semgrep's keys are not all flat identifiers, which is the hole in the reasoning above:
// `c#` and `c++` are keys it accepts, and both slug to `c`, which is also C. Accepting the
// aliases in the extension table reopened exactly the collision that comment warns about, so
// every alias resolves to one canonical key before anything is named after it.
const CANONICAL_BY_LANGUAGE = {
  'c#': 'csharp',
  'c++': 'cpp',
  docker: 'dockerfile',
  ex: 'elixir',
  golang: 'go',
  hcl: 'terraform',
  js: 'javascript',
  kt: 'kotlin',
  proto: 'protobuf',
  proto3: 'protobuf',
  py: 'python',
  python2: 'python',
  python3: 'python',
  sh: 'bash',
  sol: 'solidity',
  tf: 'terraform',
  ts: 'typescript',
}

function canonicalLanguage(key) {
  const normalized = (key || '').toLowerCase().trim()
  return Object.hasOwn(CANONICAL_BY_LANGUAGE, normalized)
    ? CANONICAL_BY_LANGUAGE[normalized]
    : normalized
}

// Canonicalising is not enough on its own: ["Go", "golang"], or the same language twice, still
// resolve to one stem. pipeline() runs languages concurrently with no barrier, so both would
// write the same rule and test file while each reported its own outcome — two passes over one
// clobbered directory. Claiming is synchronous, so the second claimant loses rather than races.
const claimedStems = new Map()

function claimStem(stem, language) {
  const owner = claimedStems.get(stem)
  if (owner) {
    throw new Error(
      `resolves to the same directory as ${owner} (${stem}), and both would write the same rule and test file. Pass one entry per Semgrep language.`,
    )
  }
  claimedStems.set(stem, language)
  return stem
}

// Semgrep decides which files a rule applies to by extension, and skips the rest. A test
// file whose extension does not match the rule's language is therefore never graded, and
// `semgrep --test` prints "All tests passed" for the zero tests it ran — a green that means
// the rule was never applied to anything. Deriving the extension here from Semgrep's own
// language key removes the guess; an unknown key stops that language instead of writing a
// file that would pass vacuously.
//
// Every alias Semgrep accepts, not just the canonical name, because the assessment reports
// whichever one it read: `sol`, `py`, `kt`, `ex`, `tf` and `golang` are all real keys, and a
// table holding only `solidity` and `python` rejects half the correct answers. Deliberately
// absent are `generic`, `regex` and `none` — those are matching modes rather than languages,
// with no extension of their own and no AST to write patterns against.
const EXTENSION_BY_LANGUAGE = {
  apex: 'cls',
  bash: 'sh',
  c: 'c',
  'c#': 'cs',
  'c++': 'cpp',
  cairo: 'cairo',
  circom: 'circom',
  clojure: 'clj',
  cpp: 'cpp',
  csharp: 'cs',
  dart: 'dart',
  docker: 'dockerfile',
  dockerfile: 'dockerfile',
  elixir: 'ex',
  ex: 'ex',
  go: 'go',
  golang: 'go',
  hcl: 'tf',
  html: 'html',
  java: 'java',
  javascript: 'js',
  js: 'js',
  json: 'json',
  jsonnet: 'jsonnet',
  julia: 'jl',
  kotlin: 'kt',
  kt: 'kt',
  lua: 'lua',
  move_on_aptos: 'move',
  move_on_sui: 'move',
  ocaml: 'ml',
  php: 'php',
  powershell: 'ps1',
  proto: 'proto',
  proto3: 'proto',
  protobuf: 'proto',
  py: 'py',
  python: 'py',
  python2: 'py',
  python3: 'py',
  r: 'r',
  ruby: 'rb',
  rust: 'rs',
  scala: 'scala',
  sh: 'sh',
  sol: 'sol',
  solidity: 'sol',
  swift: 'swift',
  terraform: 'tf',
  tf: 'tf',
  ts: 'ts',
  typescript: 'ts',
  vue: 'vue',
  xml: 'xml',
  yaml: 'yaml',
}

// The rule always lands at `${stem}.yaml`, so a yaml target's test file is that same path: the
// translate phase overwrites the spec the test phase wrote, and the rule is graded against
// itself over no surviving annotations, which can still end in "All tests passed". It is the
// only entry in the table that collides; json, xml and html do not.
const RULE_FILE_EXTENSION = 'yaml'

// The table is the whole answer, with no fall back to an extension the assessment claimed.
// That fallback made the guard above self-defeating: the prompt asked every assessment for an
// extension, so one was nearly always there to fall back to, and a target Semgrep cannot read
// at all still produced a test file — `.pl` for Perl — that Semgrep skipped and `--test` then
// called a pass. An unrecognised key stopping the language is the behaviour the comment above
// has always claimed.
//
// hasOwn rather than a truthiness test: `constructor` and `__proto__` are strings an
// assessment can report, and both find something on the prototype chain.
function testFileExtension(language, assessment) {
  const key = (assessment.semgrepLanguage || '').toLowerCase().trim()
  // A throw rather than a fallback, so the one return here stays the bare table lookup.
  if (Object.hasOwn(EXTENSION_BY_LANGUAGE, key)) {
    if (EXTENSION_BY_LANGUAGE[key] === RULE_FILE_EXTENSION) {
      throw new Error(
        `${language}: a test file for "${key}" would end in .${RULE_FILE_EXTENSION}, the same as ` +
          'the rule this directory holds, so the translated rule would overwrite the tests that ' +
          'specify it and then be graded against itself. Porting to it needs a directory layout ' +
          'that separates the two, which this script does not have.',
      )
    }
    return EXTENSION_BY_LANGUAGE[key]
  }

  const shown = key.length > 60 ? `${key.slice(0, 60)}…` : key
  throw new Error(
    `${language}: "${shown}" is not a Semgrep language key this script knows a test file ` +
      'extension for. Writing the test file anyway would produce a file semgrep skips, and ' +
      '`semgrep --test` reports a pass for zero tests run, so this language stops here instead.',
  )
}

// Semgrep says a rule it never ran passed: a Pro-gated parser leaves the run ending in "All
// tests passed" over zero graded tests. These are the two phrasings observed from semgrep
// 1.172.0 — `Missing plugin for rule <id>` / `Missing Semgrep extension needed for parsing
// <lang> target` under --test, and `N rule(s) were skipped because they require Pro` on a scan.
//
// Deliberately narrow. A bare `--pro` matches Pro upsell hints, and a bare `were skipped`
// matches file-level skip notices and partial-parse summaries, both of which appear in the
// last 20 lines an agent reports verbatim — either would fail a genuinely green port through
// all three retries. Missing an unseen phrasing only falls back to the version check; failing
// a good port has no fallback.
//
// Matched against the tail the agent reports, and semgrep prints these above the per-target
// results, so validatePrompt asks for any such line to be carried in wherever it appeared. The
// version check is no backstop here: the agent used the right binary and said so.
const SKIPPED_RATHER_THAN_RUN = /missing plugin|missing semgrep extension|skipped because they require/i

// Anchored, then semgrep-qualified: an unanchored triple takes the 3.11.5 out of
// "Python 3.11.5 / semgrep 1.172.0" and fails a green port against a version nothing ran.
function semgrepVersion(reported) {
  const text = String(reported || '').trim()
  const bare = /^v?(\d+\.\d+\.\d+)/.exec(text)
  if (bare) return bare[1]
  const qualified = /semgrep\D{0,20}(\d+\.\d+\.\d+)/i.exec(text)
  return qualified ? qualified[1] : ''
}

/**
 * Return why semgrep's JSON does not show this variant's spec graded clean, or '' when it does.
 *
 * The text and version checks establish that semgrep ran and which binary spoke. Neither
 * establishes that an annotation was graded, and that is the third vacuous green: a spec with no
 * `ruleid:` comments, or one naming the original rule instead of this variant, grades zero and
 * still ends in "All tests passed". The validate prompt also allows fixing a wrong test case, so
 * an agent out of ideas can delete the annotation it cannot satisfy and go green. The golden
 * fixtures are already judged this way in test_port_rule_workflow.py; this is the same verdict on
 * the path that actually produces ports.
 *
 * Targets are matched on `<stem>.` because the spec is always `${stem}.${extension}` and the
 * rule id is the stem, so the filename never has to be threaded through the pipeline.
 */
function gradingFailure(reported, stem) {
  let report
  try {
    report = JSON.parse(reported || '')
  } catch {
    return 'the --test --json output did not parse, so nothing shows an annotation was graded'
  }

  if (report?.config_with_errors?.length) return 'semgrep could not load the rule itself'

  // hasOwn, for the reason testFileExtension uses it: `constructor` resolves on any object.
  const checks = Object.values(report?.results || {})
    .map((entry) => entry?.checks || {})
    .find((candidate) => Object.hasOwn(candidate, stem))
  if (!checks) {
    return `semgrep graded no check under ${stem}, so it skipped the rule rather than running it`
  }

  const check = checks[stem]
  const graded = Object.entries(check?.matches || {}).find(([target]) =>
    String(target).split('/').pop().startsWith(`${stem}.`),
  )
  if (!graded) return `no target named ${stem}.* is among the files semgrep graded`

  const expected = graded[1]?.expected_lines || []
  const found = graded[1]?.reported_lines || []
  const name = graded[0].split('/').pop()
  if (expected.length === 0) {
    return `${name} has no annotated lines, so a pass over it grades nothing`
  }

  // Two, not one. testPrompt asks for at least two of each case and test_port_rule_workflow.py
  // holds the golden fixtures to that, so accepting one here would let the live path pass a spec
  // the plugin's own fixture standard rejects — the same split this verdict exists to close.
  // Only the ruleid side is here; safeCaseFailure counts the `ok:` lines, absent from expected_lines.
  if (expected.length < 2) {
    return `${name} has one annotated line, where a spec is meant to cover at least two vulnerable cases`
  }
  if (expected.join(',') !== found.join(',')) {
    return `expected matches on lines [${expected}], semgrep reported [${found}]`
  }
  if (!check.passed) return `semgrep marked ${stem} failed`
  return ''
}

/**
 * Return why semgrep's count of this spec's safe cases falls short, or '' when it does not.
 *
 * The verdict above reads the `ruleid:` side out of `expected_lines`, and there is no `ok:` side to
 * read: an annotated safe line is neither expected nor reported. So vulnerable cases alone grade
 * clean, for a rule that may flag every process launch in the target language — the false positive
 * SKILL.md says a port most often invents, and one the golden fixtures are held to two of each for.
 *
 * Semgrep's count rather than the agent's, for the reason `passed` is absent, and taken at
 * validation because validatePrompt permits deleting a test case after the test phase reported it.
 */
function safeCaseFailure(reported, stem) {
  let report
  try {
    report = JSON.parse(reported || '')
  } catch {
    return 'the safe-case probe output did not parse, so nothing shows the spec covers a safe case'
  }

  // Before the count, since semgrep prints it over a run that matched nothing: a probe pointed
  // somewhere else otherwise reads as zero safe cases in a spec holding five.
  const scanned = (report?.paths?.scanned || []).map((path) => String(path).split('/').pop())
  if (!scanned.some((name) => name.startsWith(`${stem}.`))) {
    return `the safe-case probe scanned ${scanned.join(', ') || 'nothing'} rather than ${stem}.*, so its count is about some other file`
  }

  // Distinct positions, not the length of `results`: entries carrying no line are a cheap two.
  const annotated = new Set(
    (report?.results || [])
      .map((match) => match?.start?.line)
      .filter((line) => typeof line === 'number'),
  )
  if (annotated.size < 2) {
    return `semgrep found ${annotated.size} \`ok: ${stem}\` annotation(s) in the spec, where two safe cases are the floor — a rule broad enough to flag every construct passes a spec with none`
  }
  return ''
}

/**
 * Return why the validation did not pass, or an empty string when it did.
 *
 * Read out of semgrep's own output rather than a self-reported boolean, and out of the same
 * semgrep the rule was read with. Quoting semgrep only binds the agent while the binary is
 * fixed: one that could not make its tests pass installed an older build whose parser for the
 * target language was not yet Pro-gated, ran there, and reported a true "All tests passed" for
 * a port that is red on the semgrep it has to run under.
 *
 * An unreported version fails rather than passes. A check that cannot tell which semgrep spoke
 * has not checked anything.
 */
function validationFailure(validation, expectedVersion, stem) {
  const output = validation?.testOutput || ''
  if (!output) return 'the agent did not report back'
  if (SKIPPED_RATHER_THAN_RUN.test(output)) {
    return 'semgrep skipped the rule rather than running it, so nothing was graded'
  }
  if (!/All tests passed/.test(output)) {
    // Attributed, because the verdict is semgrep's and this sentence is not. Unlabelled, an
    // agent's "the rule is correct, semgrep's Go parser is wrong" reads as a finding.
    return validation?.summary
      ? `semgrep did not report that all tests passed; the agent said: ${validation.summary}`
      : 'semgrep did not report that all tests passed'
  }

  const want = semgrepVersion(expectedVersion)
  const got = semgrepVersion(validation?.semgrepVersion)
  if (!want) return 'no baseline semgrep version was recorded when the rule was read'
  if (got !== want) {
    return `graded with semgrep ${got || '(unreported)'}, not the ${want} this port is measured against`
  }
  // Graded at all before covered well: a spec semgrep never reached makes the count meaningless.
  const ungraded = gradingFailure(validation?.testJson, stem)
  if (ungraded) return ungraded
  return safeCaseFailure(validation?.safeCaseJson, stem)
}

function validationPassed(validation, expectedVersion, stem) {
  return validationFailure(validation, expectedVersion, stem) === ''
}

// Splits the pipeline's results. A stage that throws drops its item to null, so filtering
// happens here before anything reads a field, and the dropped ones are named rather than
// quietly forgotten — index-aligned to `requested`, since a dead stage set no field to
// identify itself by, and a bare count leaves the reader working out which language to re-run.
function partition(results, requested) {
  const done = results.filter(Boolean)
  const ported = done.filter((r) => !r.skipped && !r.unsupported && !r.stopped)
  return {
    passed: ported.filter((r) => r.validation?.passed),
    failed: ported.filter((r) => !r.validation?.passed),
    skipped: done.filter((r) => r.skipped),
    unsupported: done.filter((r) => r.unsupported),
    stopped: done.filter((r) => r.stopped),
    lost: requested.filter((_, index) => !results[index]),
  }
}

// Four ways a language ends without a variant, and they call for four different things: fix
// the rule (failed), accept it (not applicable), reach for another tool (unsupported), fix the
// invocation (stopped), re-run (lost). Collapsing any of them into `lost` tells the reader to
// re-run something that will deterministically stop again.
function stop(language, assessment, reason) {
  log(`${language}: stopped — ${reason}`)
  return { language, assessment, stopped: true, reason }
}

// The class exists here and semgrep cannot read the language, which is a different finding from
// NOT_APPLICABLE and calls for a different follow-up. Shared, because two phases can reach it:
// the assessment's own answer, and the refuter's when it renames the target.
function unsupportedResult(language, assessment) {
  log(`${language}: semgrep cannot analyse it — ${assessment.semgrepCheck || assessment.reasoning}`)
  return { language, assessment, unsupported: true }
}

// The rule travels as a path, never as text an agent retyped into a prompt. See RULE_SCHEMA.
function ruleFile() {
  return `The rule being ported is at ${args.rulePath}. Read it there — work from the file, not from a description of it.\n\n`
}

function applicabilityPrompt(rule, language) {
  return `Assess whether this Semgrep rule's vulnerability pattern applies to ${language}.

${ruleFile()}Decide on three grounds:
1. Does the vulnerability class exist in ${language} at all?
2. Does an equivalent construct exist for each source, sink, and sanitizer?
3. Would a ported rule detect real risk, rather than a surface syntax match?

Return APPLICABLE when the constructs map with the same semantics, APPLICABLE_WITH_ADAPTATION when the class exists but the APIs differ enough to need new pattern shapes, NOT_APPLICABLE when the class does not exist in ${language}. Name the equivalent constructs you found as "original -> target" entries, and give Semgrep's own language key for ${language}, exactly as Semgrep spells it and with nothing else in the field.

Separately from that verdict, establish whether the installed semgrep can analyse ${language} at all, and report it as semgrepCanAnalyze. Run it rather than recalling it: check \`semgrep show supported-languages\` for the key, then confirm a rule declaring that key actually runs, because some parsers ship only in Pro and a rule semgrep skipped still ends its \`--test\` run in "All tests passed". Report the command and the line it printed as semgrepCheck. A language semgrep cannot read stops the port whatever the verdict, and it stops with no second opinion, so the evidence has to be there for someone to recheck in one step. Say which of the two questions is failing.

${reference('applicability-analysis.md', 'holds worked examples of each verdict')}${SCOPE}`
}

function refutationPrompt(rule, language, assessment) {
  return `Another agent judged this Semgrep rule unportable to ${language}, and on that verdict the port is about to be dropped with no further work and no output. Test the verdict.

Its reasoning: ${assessment.reasoning}

${ruleFile()}The verdict is wrong if the vulnerability class does exist in ${language} under a different name, or if an equivalent construct exists for every source and sink in a library or idiom the first agent did not consider. The verdict is right if ${language} has no such construct, or if the risk the rule describes cannot arise there.

A matching construct is necessary and not sufficient. The source you would taint has to be attacker-controlled: untrusted input that reaches the code from outside the system. A developer-set environment variable, a hardcoded test fixture, config the deploying team owns, or any other value supplied by the people running the code is not attacker-controlled, and a reachable sink fed only from such a source does not make the rule applicable. When that is the situation, say so explicitly and leave the verdict standing.

Refute it only when you can name the ${language} constructs a ported rule would match, as "original -> target" entries, and say who controls each source and why they are untrusted. An overturn with no constructs named is treated as leaving the verdict standing, because the phase after this one writes its tests from that list. Otherwise return refuted: false and name the part of the verdict that holds.

If the verdict named the wrong Semgrep language key and you give a different one, establish whether the installed semgrep can parse *that* key and report it as semgrepCanAnalyze with the command as semgrepCheck. The check that would have caught a Pro-only parser already ran, against the key you are replacing.

${reference('applicability-analysis.md', 'holds worked examples of each verdict')}${SCOPE}`
}

function testPrompt(rule, language, assessment, dir, stem, extension) {
  return `Write the test file for a ${language} port of the Semgrep rule "${rule.id}". No rule exists yet — the tests define what it must detect.

${ruleFile()}Equivalent ${language} constructs identified: ${JSON.stringify(assessment.equivalentConstructs || [])}
${assessment.verdict === 'APPLICABLE_WITH_ADAPTATION' ? `Adaptation needed: ${assessment.reasoning}` : ''}

Create ${dir}/ and write ${dir}/${stem}.${extension} containing code a ${language} developer would recognise as idiomatic: real imports, real handler shapes, the constructs above used the way they are actually used.

Annotate it so semgrep --test can grade the rule. Put a comment reading \`ruleid: ${stem}\` on the line immediately before each line that must be flagged, and \`ok: ${stem}\` on the line immediately before each line that must not be. Include at least two of each. Cover more than one sink and more than one safe form, including whichever safe form is the ${language} idiom for doing this correctly.

${SCOPE}`
}

function translatePrompt(rule, language, assessment, test, dir, stem) {
  return `Write the ${language} variant of Semgrep rule "${rule.id}". Its test file already exists and defines the target behaviour.

Test file: ${test.filePath}
Test cases: ${test.summary}

${ruleFile()}Start by reading the target AST, since pattern shape follows AST shape rather than source resemblance:
\`\`\`
semgrep --dump-ast -l ${assessment.semgrepLanguage} ${test.filePath}
\`\`\`

Write ${dir}/${stem}.yaml with id \`${stem}\`, \`languages: [${assessment.semgrepLanguage}]\`, and metadata carrying \`original-rule: ${rule.id}\` and \`ported-from: ${rule.sourceLanguage || 'original'}\`. Preserve the original's detection intent and its mode${rule.mode ? ` (${rule.mode})` : ''}. Write the patterns the way a ${language} rule author would: match the constructs the language actually uses, and cover the variants named in ${JSON.stringify(assessment.equivalentConstructs || [])}.

Leave running the tests to the next phase. When the phase is done the directory holds
exactly the rule and its test file, so keep any prototyping you do elsewhere.

${reference('language-syntax-guide.md', 'covers translating patterns across languages')}${SCOPE}`
}

// `rejection` has to travel: three of the four grounds are ones the previous agent could not
// see. A round that went green on the wrong binary reports "clean", so relaying only its own
// words told the retry "stopped before the tests passed, leaving: clean" and nothing to act on.
// Takes the pipeline item rather than its fields: the prompt needs the test file, the rule, and
// the stem the annotations are keyed on, and spreading those into positional parameters puts this
// over the five-argument limit.
function validatePrompt(language, ported, previous, rejection) {
  const { test, artifact, stem } = ported
  return `Make the ${language} Semgrep rule at ${artifact.filePath} pass its tests.
${
  rejection
    ? `\nAn earlier round was rejected, on a ground the agent that ran it could not always see: ${rejection}. What that agent reported: ${previous?.summary || '(it did not report back)'}. Any edits it made to the rule are already on disk, so continue from the current state rather than starting over.\n`
    : ''
}
\`\`\`
semgrep --validate --config ${artifact.filePath}
semgrep --test --config ${artifact.filePath} ${test.filePath}
semgrep --test --json --config ${artifact.filePath} ${test.filePath}
semgrep --lang generic --pattern 'ok: ${stem}' --json ${test.filePath}
\`\`\`

Read what the failure tells you: missed lines mean the pattern is narrower than the vulnerability, incorrect lines mean it is broader. For taint rules, \`semgrep --dataflow-traces -f ${artifact.filePath} ${test.filePath}\` shows where taint stops flowing. Edit the rule and re-run until semgrep reports that all tests passed.

The test file is the specification: fix the rule to satisfy it. Change a test case only if the case itself is wrong, such as an annotation on the wrong line, and say so if you do.

Iterate in place, and leave the directory holding exactly the rule and its test file — put any alternative rules you try somewhere outside it.

The semgrep already on PATH is the acceptance criterion. Do not install, pin, downgrade or otherwise switch semgrep to get a pass. If that semgrep cannot run this rule — a Pro-only parser for the target language, say — that is the result: report the failing output and say so. A port graded by a different binary is a port nobody can reproduce.

Report the output of the final \`semgrep --test\` run verbatim as testOutput, trimmed to its last 20 lines if it is longer than that. Do not summarise it or restate the verdict in your own words there: the caller decides whether the port passed by reading semgrep's own words. Report the exact command you ran, and what \`semgrep --version\` prints for the binary that ran it. Also report how many test runs it took and what you changed.

One exception to the last-20-lines trim. If the run printed a line saying rules were skipped, or naming a missing plugin or a missing Semgrep extension, include that line in testOutput too, wherever in the output it appeared. Semgrep prints those above the per-target results, so a tail can cut them off — and they are how the caller tells a rule semgrep graded from one it never ran, which otherwise also ends in "All tests passed".

Then run the same test once more with \`--json\` and report its complete stdout verbatim as testJson. Do not trim, reformat or summarise it. The caller reads which lines semgrep expected and which it actually matched out of that structure, because "All tests passed" is what semgrep prints over a spec with nothing annotated too — so a run whose annotations went missing, or whose \`ruleid:\` names the original rule rather than \`${stem}\`, reads as a pass in the summary line and as graded-nothing here.

That structure has no \`ok:\` side to read — an annotated safe line is neither expected nor matched — so run the last command as well and report its complete stdout verbatim as safeCaseJson, untrimmed. It is semgrep counting the spec's safe cases, and two is the floor there for the same reason it is on the vulnerable side: a rule broad enough to flag every ${language} construct of this shape passes a spec that annotates none. If the spec is short of two \`ok: ${stem}\` cases, add them — including the ${language} idiom for doing this correctly — rather than reporting a green the caller cannot read as one.

${SCOPE}`
}

async function recheckApplicability(rule, language, assessment) {
  const refutation = await agent(refutationPrompt(rule, language, assessment), {
    schema: REFUTATION_SCHEMA,
    effort: 'high',
    phase: 'Recheck applicability',
    label: `refute:${language}`,
  })

  // A dead refuter is not an upheld verdict. A spawn returns null when a subagent dies on a
  // terminal error after retries, and folding that into "the verdict stands" drops the
  // language on a verdict nothing ever second-guessed — reported identically to one that was,
  // which is the single thing this phase exists to prevent.
  if (!refutation) {
    return null
  }

  if (!refutation.refuted) {
    return assessment
  }

  // An overturn names the constructs or it is not an overturn. The prompt asks for them and the
  // schema cannot make them conditionally required, and this is the one path where the fallback
  // below is empty: the agent being overturned concluded the rule does not port, so it enumerated
  // nothing. Without this, the test-first phase writes its spec from `[]`.
  const constructs = refutation.equivalentConstructs || assessment.equivalentConstructs || []
  if (constructs.length === 0) {
    log(`${language}: overturn named no equivalent constructs, so the verdict stands`)
    return assessment
  }

  // The refuter's key wins: the agent it overturned had concluded the rule does not port, so its
  // language key was never load-bearing and may not even be right. But a key nothing has probed
  // cannot inherit the parse answer for the key it replaces — the gate runs before this phase, and
  // inheriting `true` through a rename is how a Pro-only parser reached translation and three
  // xhigh validation rounds, landing in `failed` when the truth was `unsupported`.
  const key = refutation.semgrepLanguage || assessment.semgrepLanguage
  const renamed = canonicalLanguage(key) !== canonicalLanguage(assessment.semgrepLanguage)

  log(`${language}: NOT_APPLICABLE overturned on recheck — ${refutation.reasoning}`)
  return {
    ...assessment,
    verdict: 'APPLICABLE_WITH_ADAPTATION',
    reasoning: refutation.reasoning,
    equivalentConstructs: constructs,
    semgrepLanguage: key,
    semgrepCanAnalyze: renamed ? refutation.semgrepCanAnalyze : assessment.semgrepCanAnalyze,
    semgrepCheck: renamed ? refutation.semgrepCheck : assessment.semgrepCheck,
  }
}

const languages = (Array.isArray(args?.languages) ? args.languages : [args?.languages])
  .map((language) => String(language ?? '').trim())
  .filter(Boolean)

// One message per missing argument: a combined one opens by naming args.rulePath, sending a
// caller with a good rule path and an empty language list to check the wrong argument.
const RESUME_NOTE =
  'Resuming needs it too: args are not saved with a run, so pass them again alongside resumeFromRunId.'

if (!args?.rulePath) {
  throw new Error(
    `port-rule-to-languages needs args.rulePath: the path to the Semgrep rule YAML being ported. ${RESUME_NOTE}`,
  )
}

if (languages.length === 0) {
  throw new Error(
    `port-rule-to-languages needs args.languages: one or more target languages, one per entry. ${RESUME_NOTE}`,
  )
}

// One language per entry. "Go and Java" and '["go","java"]' both survive the check above as
// a single item, and would silently port one language named after the whole phrase.
//
// A genuine multi-word name is rejected too, deliberately: each has a single-token Semgrep key
// and that key names the directory. The message covers both, since telling someone who typed
// "Objective C" that their entry holds two languages sends them after a phrase they never wrote.
const malformed = languages.filter((language) => /[\s,[\]"']/.test(language))
if (malformed.length > 0) {
  throw new Error(
    `port-rule-to-languages needs one language per entry in args.languages, each a single token; these are not: ${JSON.stringify(malformed)}. Pass ["Go", "Java"] rather than "Go and Java" or a JSON string, and spell a multi-word name the way Semgrep does — "csharp" or "C#", not "C Sharp".`,
  )
}

if (!referencesDir) {
  throw new Error(
    'port-rule-to-languages needs args.referencesDir: an absolute path to a directory holding applicability-analysis.md and language-syntax-guide.md. Without it every phase runs without the guidance the port depends on, and nothing downstream fails — the run reports every language passed either way — so it stops here instead.',
  )
}

// Non-empty is not resolvable. A script cannot expand `{baseDir}` and has no filesystem access
// to notice it did not, so the literal reaches every prompt as a path that is not there and the
// run reports every language passed. Deterministic, so it is checked rather than warned about.
if (referencesDir.includes('{') || !referencesDir.startsWith('/')) {
  throw new Error(
    `port-rule-to-languages needs args.referencesDir as a resolved absolute path, and got ${JSON.stringify(args.referencesDir)}. A workflow script cannot expand {baseDir} or \${CLAUDE_PLUGIN_ROOT}, so resolve it before the call and pass the path as printed.`,
  )
}

const outputDir = args.outputDir || '.'

phase('Read rule')
const rule = await agent(
  `Read the Semgrep rule at ${args.rulePath} and report its structure: the rule id, its mode if it uses taint mode, the language in its languages: key, and its sources, sinks, and sanitizers as plain pattern strings.

Then run \`semgrep --version\` and report what it prints as semgrepVersion. That binary is the one every port in this run is graded against.`,
  { schema: RULE_SCHEMA, effort: 'low', label: 'read-rule' },
)

if (!rule) {
  throw new Error(
    `Could not read the Semgrep rule at ${args.rulePath}: the reader agent did not report back.`,
  )
}

// Every round measures the port against this version, so an unreadable one refuses every round
// of every language on a condition settled before the first agent spawns. The schema requires
// the field to be present, not to hold a version — "unknown" satisfies it.
const baseline = semgrepVersion(rule.semgrepVersion)
if (!baseline) {
  throw new Error(
    `No semgrep version could be read from the reader agent's report (${JSON.stringify(rule.semgrepVersion)}). Every port in a run is graded against the semgrep that read the rule, so without one each language would spend ${MAX_VALIDATE_ROUNDS} validation rounds being refused for the same reason. Check that \`semgrep --version\` runs on this machine, then re-run.`,
  )
}

log(`${rule.id} (${rule.sourceLanguage || 'unknown'}${rule.mode ? `, ${rule.mode} mode` : ''}) -> ${languages.join(', ')}, graded by semgrep ${baseline}`)
log(`${languages.length} language(s): 4 agents each when a port goes green first try, up to ${MAX_AGENTS_PER_LANGUAGE} when a verdict needs rechecking and validation needs its retries`)

const results = await pipeline(
  languages,
  (language) =>
    agent(applicabilityPrompt(rule, language), {
      schema: APPLICABILITY_SCHEMA,
      effort: 'high',
      phase: 'Assess applicability',
      label: `assess:${language}`,
    }),

  async (assessment, language) => {
    if (!assessment) {
      throw new Error(`${language}: the applicability agent did not report back`)
    }

    // Ahead of the verdict, and ahead of the refuter: a language semgrep cannot parse yields
    // no rule whatever the vulnerability class does there, so refuting the verdict would
    // settle nothing and cost an agent. This is the gap a Pro-only parser walked through —
    // the port was graded by a semgrep that could read the language rather than by this one.
    // Absent is not a yes. The schema requires this field, so a missing one is malformed output
    // rather than permission to proceed — and reading it as permission is the unsafe direction,
    // since this is the gate that keeps a Pro-only parser out and it drops a language with no
    // refuter behind it. Checked before the `=== false` branch so the message stays accurate:
    // "semgrep cannot analyse it" and "nobody said" are different findings.
    if (typeof assessment.semgrepCanAnalyze !== 'boolean') {
      return stop(
        language,
        assessment,
        'the assessment never said whether semgrep can parse this language, and that claim is the only thing standing between a Pro-only parser and a port graded over zero rules',
      )
    }

    if (assessment.semgrepCanAnalyze === false) {
      return unsupportedResult(language, assessment)
    }

    const settled =
      assessment.verdict === 'NOT_APPLICABLE'
        ? await recheckApplicability(rule, language, assessment)
        : assessment

    if (!settled) {
      return stop(language, assessment, 'the refuter never reported, so the NOT_APPLICABLE verdict was never second-guessed')
    }

    if (settled.verdict === 'NOT_APPLICABLE') {
      log(`${language}: NOT_APPLICABLE — ${settled.reasoning}`)
      return { language, assessment: settled, skipped: true }
    }

    // Gated again, because the refuter is allowed to correct the language key and the check above
    // ran against the key the assessment probed. On the path where nothing was renamed this is the
    // same boolean twice; where something was, it is the only place the new key is asked about.
    if (settled.semgrepCanAnalyze === false) {
      return unsupportedResult(language, settled)
    }

    // And a rename with no answer at all is not an answer. Scoped to a rename on purpose: absent
    // is only suspicious once something changed the target, and the message would misdescribe any
    // other path.
    const renamed =
      canonicalLanguage(settled.semgrepLanguage) !== canonicalLanguage(assessment.semgrepLanguage)
    if (renamed && settled.semgrepCanAnalyze !== true) {
      return stop(
        language,
        settled,
        `the recheck moved the Semgrep language key to "${settled.semgrepLanguage}" without establishing that semgrep can parse it, and the gate that would have caught a Pro-only parser ran against "${assessment.semgrepLanguage}"`,
      )
    }

    // Both guards run before the paths are built from them, so an unusable language key or a
    // directory two languages would share stops the port rather than naming a directory. The
    // throws are caught here rather than left to drop the item: an uncaught one reaches the
    // caller only as "did not report back", which reads as an agent that died and is worth
    // re-running, when it is a deterministic refusal with a message worth reading.
    let extension, stem, dir
    try {
      extension = testFileExtension(language, settled)
      stem = claimStem(`${rule.id}-${slug(canonicalLanguage(settled.semgrepLanguage) || language)}`, language)
      dir = `${outputDir}/${stem}`
    } catch (error) {
      return stop(language, settled, error.message)
    }

    const test = await agent(testPrompt(rule, language, settled, dir, stem, extension), {
      schema: ARTIFACT_SCHEMA,
      effort: 'high',
      phase: 'Write tests',
      label: `test:${language}`,
    })
    return { language, assessment: settled, stem, dir, test }
  },

  async (prev, language) => {
    if (prev.skipped || prev.unsupported || prev.stopped) return prev
    const artifact = await agent(
      translatePrompt(rule, language, prev.assessment, prev.test, prev.dir, prev.stem),
      {
        schema: ARTIFACT_SCHEMA,
        effort: 'xhigh',
        phase: 'Translate rule',
        label: `translate:${language}`,
      },
    )
    return { ...prev, artifact }
  },

  async (prev, language) => {
    if (prev.skipped || prev.unsupported || prev.stopped) return prev

    let validation = null
    let rejection = ''
    let rounds = 0

    while (rounds < MAX_VALIDATE_ROUNDS) {
      rounds += 1
      const reported = await agent(
        validatePrompt(language, prev, validation, rejection),
        {
          schema: VALIDATION_SCHEMA,
          effort: 'xhigh',
          phase: 'Validate',
          label: `validate:${language}`,
        },
      )

      validation = reported
        ? { ...reported, passed: validationPassed(reported, rule.semgrepVersion, prev.stem) }
        : null
      if (validation?.passed) break

      rejection = validationFailure(reported, rule.semgrepVersion, prev.stem)
      log(
        rounds < MAX_VALIDATE_ROUNDS
          ? `${language}: validation round ${rounds} did not pass — ${rejection}; retrying`
          : `${language}: still failing after ${MAX_VALIDATE_ROUNDS} validation rounds — ${rejection}`,
      )
    }

    return { ...prev, validation, rounds }
  },
)

const { passed, failed, skipped, unsupported, stopped, lost } = partition(results, languages)

log(`${passed.length} passed, ${failed.length} failed validation, ${skipped.length} not applicable, ${unsupported.length} unsupported by semgrep${stopped.length > 0 ? `, ${stopped.length} stopped` : ''}${lost.length > 0 ? `, ${lost.length} did not report back (${lost.join(', ')})` : ''}`)

return {
  rule: rule.id,
  semgrepVersion: baseline,
  passed: passed.map((r) => ({
    language: r.language,
    directory: r.dir,
    rule: r.artifact.filePath,
    test: r.test.filePath,
    iterations: r.validation.iterations,
    validationRounds: r.rounds,
  })),
  failed: failed.map((r) => ({
    language: r.language,
    directory: r.dir,
    validationRounds: r.rounds,
    reason: validationFailure(r.validation, rule.semgrepVersion, r.stem),
  })),
  notApplicable: skipped.map((r) => ({ language: r.language, reasoning: r.assessment.reasoning })),
  // Distinct from notApplicable: the pattern may port perfectly well and semgrep still cannot
  // read the language, and the two call for different follow-ups.
  unsupported: unsupported.map((r) => ({
    language: r.language,
    reasoning: r.assessment.reasoning,
    semgrepCheck: r.assessment.semgrepCheck,
  })),
  // Deterministic refusals, kept out of `incomplete`. Both say no variant was produced, but
  // this one will refuse again on a re-run and names what to change; `incomplete` is an agent
  // that died and is worth retrying as-is.
  stopped: stopped.map((r) => ({ language: r.language, reason: r.reason })),
  // The languages, not how many: this is the one outcome whose follow-up is "run these again".
  incomplete: lost,
}
