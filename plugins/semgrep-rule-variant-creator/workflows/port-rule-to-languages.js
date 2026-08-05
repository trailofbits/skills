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
  required: ['testOutput', 'semgrepVersion', 'command', 'iterations', 'summary'],
  properties: {
    testOutput: {
      type: 'string',
      description: 'The final semgrep --test run output, verbatim, last 20 lines or fewer',
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
  if (Object.hasOwn(EXTENSION_BY_LANGUAGE, key)) return EXTENSION_BY_LANGUAGE[key]

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
const SKIPPED_RATHER_THAN_RUN = /missing plugin|missing semgrep extension|skipped because they require/i

// Anchored first, then semgrep-qualified. `semgrep --version` prints a bare triple and the
// prompt asks for exactly that, but a reply that puts anything else first — "Python 3.11.5 /
// semgrep 1.172.0" — hands back 3.11.5 to a bare search. A genuinely green port then burns
// every retry and lands in `failed` blaming a version nothing ran.
function semgrepVersion(reported) {
  const text = String(reported || '').trim()
  const bare = /^v?(\d+\.\d+\.\d+)/.exec(text)
  if (bare) return bare[1]
  const qualified = /semgrep\D{0,20}(\d+\.\d+\.\d+)/i.exec(text)
  return qualified ? qualified[1] : ''
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
function validationFailure(validation, expectedVersion) {
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
  return ''
}

function validationPassed(validation, expectedVersion) {
  return validationFailure(validation, expectedVersion) === ''
}

// Splits the pipeline's results. A stage that throws drops its item to null, so filtering
// happens here before anything reads a field, and the dropped ones are named rather than
// quietly forgotten.
//
// Named, not counted: every other outcome carries its language, and a bare `1` leaves the
// reader diffing the requested list against five result sets by hand to find which one to
// re-run. `requested` is the array pipeline() received, so index alignment identifies the
// dropped item without depending on a field a dead stage never set.
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

Refute it only when you can name the ${language} constructs a ported rule would match, as "original -> target" entries, and say who controls each source and why they are untrusted. Otherwise return refuted: false and name the part of the verdict that holds.

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

// `rejection` is the caller's ground for refusing the last round, and it has to travel: three of
// the four grounds are ones the previous agent could not see. A round that went genuinely green
// on the wrong binary reports "clean", so relaying only the agent's own words told the next round
// "an earlier agent stopped before the tests passed, leaving: clean" — a contradiction carrying
// nothing to act on, repeated until the retries ran out.
function validatePrompt(language, test, artifact, previous, rejection) {
  return `Make the ${language} Semgrep rule at ${artifact.filePath} pass its tests.
${
  rejection
    ? `\nAn earlier round was rejected, on a ground the agent that ran it could not always see: ${rejection}. What that agent reported: ${previous?.summary || '(it did not report back)'}. Any edits it made to the rule are already on disk, so continue from the current state rather than starting over.\n`
    : ''
}
\`\`\`
semgrep --validate --config ${artifact.filePath}
semgrep --test --config ${artifact.filePath} ${test.filePath}
\`\`\`

Read what the failure tells you: missed lines mean the pattern is narrower than the vulnerability, incorrect lines mean it is broader. For taint rules, \`semgrep --dataflow-traces -f ${artifact.filePath} ${test.filePath}\` shows where taint stops flowing. Edit the rule and re-run until semgrep reports that all tests passed.

The test file is the specification: fix the rule to satisfy it. Change a test case only if the case itself is wrong, such as an annotation on the wrong line, and say so if you do.

Iterate in place, and leave the directory holding exactly the rule and its test file — put any alternative rules you try somewhere outside it.

The semgrep already on PATH is the acceptance criterion. Do not install, pin, downgrade or otherwise switch semgrep to get a pass. If that semgrep cannot run this rule — a Pro-only parser for the target language, say — that is the result: report the failing output and say so. A port graded by a different binary is a port nobody can reproduce.

Report the output of the final \`semgrep --test\` run verbatim as testOutput, trimmed to its last 20 lines if it is longer than that. Do not summarise it or restate the verdict in your own words there: the caller decides whether the port passed by reading semgrep's own words. Report the exact command you ran, and what \`semgrep --version\` prints for the binary that ran it. Also report how many test runs it took and what you changed.

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

  log(`${language}: NOT_APPLICABLE overturned on recheck — ${refutation.reasoning}`)
  return {
    ...assessment,
    verdict: 'APPLICABLE_WITH_ADAPTATION',
    reasoning: refutation.reasoning,
    equivalentConstructs: refutation.equivalentConstructs || assessment.equivalentConstructs,
    // The refuter's key wins: the agent it overturned had concluded the rule does not port,
    // so its language key was never load-bearing and may not even be right.
    semgrepLanguage: refutation.semgrepLanguage || assessment.semgrepLanguage,
  }
}

const languages = (Array.isArray(args?.languages) ? args.languages : [args?.languages])
  .map((language) => String(language ?? '').trim())
  .filter(Boolean)

// One message per missing argument. A combined "needs args.rulePath and args.languages" opens
// by naming the rule path, so a caller who passed a good one and a bad language list is sent to
// check the wrong argument.
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
// This also rejects a genuine multi-word name — "C Sharp", "Objective C" — which is deliberate,
// since every such language has a single-token Semgrep key and that key is what names the
// directory. So the message has to cover both readings: telling someone who typed "Objective C"
// that their entry holds more than one language sends them looking for a phrase they did not
// write.
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

// Non-empty is not the same as resolvable, and the difference is invisible at run time. A
// skill documenting `{baseDir}/references` hands that literal straight through, because a
// script cannot expand it and has no filesystem access to notice; every prompt then tells an
// agent to read a path that does not exist, the agent ports without the guidance, and the run
// reports every language passed. Checked here because it is deterministic, and because the
// empty-value guard above was added for this exact failure and stops one spelling of it.
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

// Every round measures the port against this version, so an unreadable one rejects every round
// of every language on a condition that cannot change between them: MAX_VALIDATE_ROUNDS xhigh
// agents per language, all refused for the same reason, knowable before the first one spawns.
// The schema requires the field to be present, not to hold a version — "unknown" satisfies it.
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
    if (assessment.semgrepCanAnalyze === false) {
      log(`${language}: semgrep cannot analyse it — ${assessment.semgrepCheck || assessment.reasoning}`)
      return { language, assessment, unsupported: true }
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
        validatePrompt(language, prev.test, prev.artifact, validation, rejection),
        {
          schema: VALIDATION_SCHEMA,
          effort: 'xhigh',
          phase: 'Validate',
          label: `validate:${language}`,
        },
      )

      validation = reported
        ? { ...reported, passed: validationPassed(reported, rule.semgrepVersion) }
        : null
      if (validation?.passed) break

      rejection = validationFailure(reported, rule.semgrepVersion)
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
    reason: validationFailure(r.validation, rule.semgrepVersion),
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
