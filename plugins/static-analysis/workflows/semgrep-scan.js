// Ships as /static-analysis:semgrep-scan. Plugin workflows are namespaced by the plugin's
// `name` field, which cannot be overridden per component, so the prefix is always
// `static-analysis:`. meta.name below supplies the rest, not the filename.
export const meta = {
  name: 'semgrep-scan',
  description:
    'Scan a codebase with Semgrep: detect languages, select rulesets, run every approved ruleset in parallel, merge to SARIF and report',
  whenToUse:
    'When the user wants a Semgrep scan run end to end without being asked to approve the ruleset list. Pass args as a JSON OBJECT, not a prose string: {"target": "/abs/path", "mode": "run-all", "out": "/abs/path"}. target defaults to cwd; mode is run-all or important-only; out defaults to an auto-incremented static_analysis_semgrep_N beside the target. The gated path, where the user reviews and edits the rulesets before anything runs, is the semgrep SKILL.md itself — use that when the ruleset selection matters.',
  phases: [
    { title: 'Detect', detail: 'resolve the output directory, check semgrep and Pro, glob languages and framework markers' },
    { title: 'Select', detail: 'choose rulesets for the detected stack from references/rulesets.md' },
    { title: 'Scan', detail: 'run scripts/run-scans.sh over the selected rulesets' },
    { title: 'Report', detail: 'post-filter, merge to SARIF, summarize, remove the cloned rule repos' },
  ],
}

// args = { target, out, mode, jobs, skill }, all optional. Prose is parsed too (`target: /x;
// mode: run-all`), since a caller passing a string would otherwise kill the run on the first line.
const ARGS_HELP =
  'Pass a JSON object like {"target": "/abs/path", "mode": "run-all"}, a bare path, or ' +
  '`target: /abs/path; mode: run-all`.'

const parseArgs = (raw) => {
  if (!raw) return {}
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string') return {}
  const text = raw.trim()
  if (!text) return {}
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text)
    } catch {
      // Fall through to key: value parsing rather than dying on a malformed brace.
    }
  }
  const KEYS = ['target', 'out', 'mode', 'jobs', 'skill']
  const out = {}
  let key = null
  for (const part of text.split(/;\s*|\n/)) {
    const m = part.match(/^\s*(\w+)\s*:\s*([\s\S]*)$/)
    if (m && KEYS.includes(m[1].toLowerCase())) {
      key = m[1].toLowerCase()
      out[key] = m[2].trim()
    } else if (key && part.trim()) {
      out[key] = `${out[key]} ${part.trim()}`.trim()
    }
  }
  if (Object.keys(out).length) return out

  // Nothing matched a key. `/static-analysis:semgrep-scan ~/proj` is the other shape a caller
  // reaches for, and the regex above cannot see it: a path opens with / ~ or . rather than a
  // word character and a colon. That fell through as {}, leaving targetHint empty, and the run
  // scanned cwd instead — a complete, clean-looking report over a tree nobody asked about,
  // which is worse than not running. A leading { is excluded so malformed JSON lands on the
  // throw below rather than becoming a target named after its own opening brace.
  const bare = !text.startsWith('{') && (/^[/~.]/.test(text) || !/\s/.test(text))
  if (bare) return { target: text }
  // Not a path and not a key: pair. Defaulting to cwd here is the same silent wrong-target
  // scan, so this is the one place the parser refuses rather than guesses.
  throw new Error(`could not parse args: ${JSON.stringify(raw)}. ${ARGS_HELP}`)
}

const input = parseArgs(args)
const MODES = new Set(['run-all', 'important-only'])
const mode = input.mode || 'run-all'
if (!MODES.has(mode)) {
  throw new Error(`mode must be one of ${[...MODES].join(', ')}, got ${JSON.stringify(input.mode)}`)
}
// A string either way, so "4" and 4 behave the same; the script validates it too.
const jobs = input.jobs === undefined || input.jobs === null ? '' : String(input.jobs).trim()
if (jobs && !/^[1-9][0-9]*$/.test(jobs)) {
  throw new Error(`jobs must be a positive integer, got ${JSON.stringify(input.jobs)}`)
}

// No approval gate: the scan is read-only over the target and every write lands inside the
// output directory. Invoking this with a target is the opt-in; SKILL.md's five steps are the
// gated path for when the ruleset list matters.
const targetHint = (input.target || '').trim()
const outHint = (input.out || '').trim()
const skillHint = (input.skill || '').trim()

const DETECT_SCHEMA = {
  type: 'object',
  required: ['target', 'outputDir', 'skillDir', 'pro', 'languages'],
  additionalProperties: false,
  properties: {
    target: { type: 'string', description: 'absolute path that was scanned for languages' },
    outputDir: { type: 'string', description: 'absolute path of the created output directory' },
    skillDir: {
      type: 'string',
      description: 'absolute path of the semgrep skill directory (the parent of scripts/), or "" if it could not be found',
    },
    pro: { type: 'boolean', description: 'true only when `semgrep --pro --validate` succeeded' },
    proReason: { type: 'string', description: 'when pro is false, the last lines of stderr explaining why; else ""' },
    languages: {
      type: 'array',
      description: 'one entry per detected language category, with the file count that justified it',
      items: {
        type: 'object',
        required: ['name', 'files'],
        additionalProperties: false,
        properties: {
          name: { type: 'string', description: 'lowercase category: python, javascript, go, docker, terraform, …' },
          files: { type: 'integer', description: 'how many files matched' },
        },
      },
    },
    frameworks: {
      type: 'array',
      description: 'frameworks read out of package.json / pyproject.toml / go.mod and the like, e.g. django, react',
      items: { type: 'string' },
    },
  },
}

const SELECT_SCHEMA = {
  type: 'object',
  required: ['rulesetsPath', 'counts'],
  additionalProperties: false,
  properties: {
    rulesetsPath: { type: 'string', description: 'absolute path of the rulesets JSON that was written' },
    counts: {
      type: 'object',
      required: ['baseline', 'language', 'thirdParty'],
      additionalProperties: false,
      properties: {
        baseline: { type: 'integer' },
        language: { type: 'integer' },
        thirdParty: { type: 'integer' },
      },
    },
  },
}

const SCAN_SCHEMA = {
  type: 'object',
  required: ['ok', 'scansJson', 'succeeded', 'failed', 'skipped'],
  additionalProperties: false,
  properties: {
    ok: {
      type: 'boolean',
      description:
        'true only when run-scans.sh exited 0. It exits non-zero when no scan succeeded, which is a failed run rather than a run that found nothing.',
    },
    scansJson: { type: 'string', description: 'absolute path of scans.json, or "" when the script did not get that far' },
    succeeded: { type: 'integer', description: 'length of .scans in scans.json, or -1 if unreadable' },
    failed: { type: 'integer', description: 'length of .failed' },
    skipped: { type: 'integer', description: 'length of .skipped' },
    error: { type: 'string', description: 'the script stderr when ok is false, else ""' },
  },
}

// ok exists for the same reason SCAN_SCHEMA's does. Without it the only fields are required
// ones, so an agent whose merge command exited non-zero has nowhere to say so and fills in
// total: 0 and a results.sarif path that was never written. The workflow would then return a
// populated success object that reads exactly like a scan which found nothing.
const REPORT_SCHEMA = {
  type: 'object',
  required: ['ok', 'resultsSarif', 'total', 'report'],
  additionalProperties: false,
  properties: {
    ok: {
      type: 'boolean',
      description:
        'true only when the merge command exited 0 and wrote the merged SARIF. A merge that failed is not a scan that found nothing.',
    },
    resultsSarif: { type: 'string', description: 'absolute path of the merged SARIF, or "" when the merge wrote none' },
    total: {
      type: 'integer',
      description: 'finding count read from the merged SARIF, never summed from per-scan counts; -1 when the merge failed',
    },
    report: { type: 'string', description: 'the markdown summary to show the user' },
    error: { type: 'string', description: 'the merge stderr when ok is false, else ""' },
  },
}

// Every later phase runs a script or reads a reference out of the semgrep skill directory, and
// where that directory is depends on how the plugin was loaded. It cannot be a constant:
// ${CLAUDE_PLUGIN_ROOT} is exported to hook, MCP and LSP subprocesses and substituted into
// skill and agent content, but a workflow script is none of those. A repo-relative path only
// resolves inside a checkout of trailofbits/skills, and a marketplace install — which is every
// real user — runs with their own project as cwd.
//
// So it is resolved at runtime, folded into the Detect phase rather than costing its own agent
// turn. The agent's Bash subprocess can read $CLAUDE_PLUGIN_ROOT even though this script cannot.
// Each candidate ends at scripts/run-scans.sh rather than the skill directory, which makes a
// stale install self-excluding: versions before that script have nothing for the search to bind
// to, and binding to one would leave the scan phase with no command to run.
const RESOLVE_SKILL_DIR = skillHint
  ? [
      `The semgrep skill directory is \`${skillHint}\`. Confirm \`${skillHint}/scripts/run-scans.sh\``,
      'exists and report it as skillDir; report "" if it does not.',
    ].join('\n')
  : [
      'Locate the semgrep skill directory. Run these in order and stop at the first that',
      '   prints a path:',
      '',
      '     ls "$CLAUDE_PLUGIN_ROOT/skills/semgrep/scripts/run-scans.sh" 2>/dev/null',
      '     ls ~/.claude/plugins/cache/*/static-analysis/*/skills/semgrep/scripts/run-scans.sh 2>/dev/null | sort -V | tail -1',
      "     find . -maxdepth 6 -type f -path '*static-analysis/skills/semgrep/scripts/run-scans.sh' 2>/dev/null | head -1",
      "     find \"$HOME\" -maxdepth 9 -type f -path '*static-analysis/skills/semgrep/scripts/run-scans.sh' 2>/dev/null | head -1",
      '',
      '   The last one takes ~15s and is the fallback for a plugin loaded with --plugin-dir from',
      '   outside the current tree, so run it only if the first three print nothing.',
      '',
      '   Report the directory two levels above the matched file (the one containing scripts/) as',
      '   skillDir. If all four print nothing, report skillDir as "" rather than guessing a path.',
    ].join('\n')

phase('Detect')
const detected = await agent(
  [
    'Resolve where this Semgrep run will write, confirm the tool is usable, and profile the codebase.',
    '',
    `Target: ${targetHint || 'the current working directory'}`,
    outHint ? `Output directory: ${outHint}` : 'Output directory: choose it as described below.',
    '',
    '1. Resolve the target to an absolute path with `cd … && pwd`. Fail if it is not a directory.',
    outHint
      ? '2. Use the output directory given above. `mkdir -p "$OUT/raw" "$OUT/results"`, then resolve it with `cd … && pwd`.'
      : [
          '2. Pick the output directory: `static_analysis_semgrep_1` beside the target, incrementing',
          '   the suffix while the name exists. `mkdir -p "$OUT/raw" "$OUT/results"`, then resolve it',
          '   with `cd … && pwd`.',
        ].join('\n'),
    '   It must be an absolute path and must not be the target itself.',
    '',
    `3. ${RESOLVE_SKILL_DIR}`,
    '',
    '4. Confirm semgrep is installed (`semgrep --version`). If it is not, stop and say so —',
    '   there is no point profiling a codebase you cannot scan.',
    '',
    '5. Check Pro. Keep stderr: "OSS only" has several causes (logged out, no subscription,',
    '   registry blocked) and the run downgrades silently for all of them.',
    '     if PRO_ERR=$(semgrep --pro --validate --metrics=off --config p/default 2>&1); then',
    '       echo "Pro available"; else echo "OSS only"; printf \'%s\' "$PRO_ERR" | tail -n 3; fi',
    '   --metrics=off matters here too: this is the first semgrep call of the run and it resolves',
    '   p/default against the registry, so without it an audit phones home before scanning.',
    '',
    '6. Detect languages by counting files. Report the count that justified each category, since',
    '   a category with one file is worth knowing about before its rulesets run. Cover every',
    '   category run-scans.sh has globs for, because one it never hears about is one it never',
    '   scans, and the report then reads clean rather than incomplete:',
    '   python, javascript, typescript, go, ruby, java, kotlin, php, c, cpp, csharp, rust,',
    '   scala, swift, elixir, apex, solidity, docker, terraform, json, cloudformation,',
    '   github-actions, kubernetes, yaml. Use lowercase category names.',
    '   Search by extension, not by name alone: .py .pyi / .js .jsx .mjs .cjs / .ts .tsx / .go /',
    '   .rb / .java .jsp / .kt .kts / .php .phtml / .c .cc .cpp .cxx .h .hh .hpp .hxx / .cs /',
    '   .rs / .scala / .swift / .ex .exs / .cls .trigger / .sol / Dockerfile *.dockerfile /',
    '   .tf .tfvars .hcl / .yaml .yml / .json. A header-only C++ tree or an ESM-only .mjs',
    '   package matches none of the obvious extensions.',
    '   Two pairs of categories OVERLAP, and the extension group above does not say which takes',
    '   which. Report the SUPERSET, never the narrower one:',
    '     c vs cpp     — report cpp unless the tree is .c/.h only. `includes_for cpp` covers',
    '                    .c .cc .cpp .cxx .h .hh .hpp .hxx, while `includes_for c` is only',
    '                    .c .h, so choosing c for a .cpp/.hpp tree scans with --include=*.c',
    '                    --include=*.h, opens zero files and exits 0. The run lands in',
    '                    coveredNothing rather than failing, so the C/C++ rules never read the',
    '                    source and nothing says the scan was empty for the wrong reason.',
    '     javascript vs typescript — javascript already carries the .ts/.tsx globs, so report',
    '                    javascript for a mixed or TS-only tree. Reporting both scans the same',
    '                    files twice under two rulesets.',
    '   YAML and JSON are assigned by CONTENT, not by extension: both are everywhere, and both',
    '   carry rulesets that must stay reachable. Glob for them, then Grep or read a sample.',
    '   YAML feeds four categories — under .github/workflows/ is github-actions, apiVersion+kind',
    '   is kubernetes, AWSTemplateFormatVersion or Resources with Type: AWS:: is cloudformation,',
    '   anything else is yaml. They are not exclusive; report each that matches.',
    '   JSON has no catch-all: "AWSTemplateFormatVersion", or "Resources" with a "Type": "AWS::"',
    '   member, is cloudformation; a "Statement" array whose elements have "Effect" is json (the',
    '   IAM policy shape r/json.aws targets); anything else — package.json, tsconfig.json,',
    '   lockfiles, editor settings — is NO category. Do not report json merely because .json',
    '   files exist, and prefer sampling paths that suggest infrastructure (iam/, policies/,',
    '   cloudformation/, infra/, *template*.json), since build config will outnumber policies.',
    '',
    '7. Read the framework markers that exist — package.json, pyproject.toml, requirements.txt,',
    '   Gemfile, composer.json, go.mod, Cargo.toml, pom.xml — and name the frameworks you find',
    '   (django, flask, react, express, nextjs, spring, laravel, …). Look at every level, not',
    '   just the target root: a monorepo keeps them in packages/*/ or services/*/. These select',
    '   extra rulesets in the next phase.',
    '',
    'Report a language only when files actually matched. An invented category costs a ruleset',
    'that scans nothing and reads in the final report as coverage that happened.',
  ].join('\n'),
  { label: 'detect', schema: DETECT_SCHEMA },
)

if (!detected) throw new Error('the detect phase returned nothing; no scan ran')
const { target, outputDir } = detected
if (!target || !target.startsWith('/')) throw new Error(`detect returned a non-absolute target: ${JSON.stringify(target)}`)
if (!outputDir || !outputDir.startsWith('/')) throw new Error(`detect returned a non-absolute output directory: ${JSON.stringify(outputDir)}`)
if (outputDir.replace(/\/+$/, '') === target.replace(/\/+$/, '')) {
  throw new Error(`output directory is the scan target (${outputDir}); the run would scan its own output`)
}

// Throwing here rather than degrading. Without the skill directory the scan phase has no
// run-scans.sh to invoke, and an agent handed the flag list and a Bash tool would compose the
// semgrep commands by hand — dropping --metrics=off, the --include scoping and the
// output-directory --exclude, which is the exact failure the script exists to prevent.
const SKILL_DIR = (detected.skillDir || '').replace(/\/+$/, '')
if (!SKILL_DIR || !SKILL_DIR.startsWith('/')) {
  throw new Error(
    'could not locate the semgrep skill directory, so run-scans.sh cannot be invoked and no scan ran. ' +
      'Pass it explicitly as {"skill": "/abs/path/to/skills/semgrep"}.',
  )
}

const langNames = (detected.languages || []).map((l) => l.name).filter(Boolean)
log(
  `target ${target}, output ${outputDir}, ${detected.pro ? 'Pro' : 'OSS'}, ` +
    `${langNames.length ? langNames.join(', ') : 'no languages detected'}` +
    `${(detected.frameworks || []).length ? ` (${detected.frameworks.join(', ')})` : ''}`,
)
if (!detected.pro && detected.proReason) log(`Pro unavailable: ${detected.proReason}`)
log(`skill directory ${SKILL_DIR}`)

phase('Select')
const selected = await agent(
  [
    'Choose the Semgrep rulesets for this codebase and write them to a file.',
    '',
    `Output directory: ${outputDir}`,
    `Target: ${target}`,
    `Detected languages: ${langNames.length ? langNames.join(', ') : '(none)'}`,
    `Detected frameworks: ${(detected.frameworks || []).join(', ') || '(none)'}`,
    '',
    `Follow the Ruleset Selection Algorithm in ${SKILL_DIR}/references/rulesets.md. Read that file;`,
    'do not select from memory. It is the same catalogue the manual path uses, so a ruleset added',
    'there has to reach this run too.',
    '',
    'It covers, in order: the security baseline that is always included, language rulesets,',
    'framework rulesets for what was detected, infrastructure rulesets, and the third-party',
    'repositories. The third-party rules from Trail of Bits, 0xdea and Decurity are required',
    'rather than optional wherever the detected language matches — they catch vulnerabilities',
    'absent from the official registry, and dropping them is the most common way this scan',
    'comes back quieter than it should.',
    '',
    `Write the result to ${outputDir}/rulesets.json in exactly this shape:`,
    '',
    '  {',
    '    "baseline": ["p/security-audit", "p/secrets"],',
    '    "python": ["p/python", "p/django"],',
    '    "javascript": ["p/javascript"],',
    '    "third_party": ["https://github.com/trailofbits/semgrep-rules"]',
    '  }',
    '',
    'Rules for that file, all enforced by the script that reads it, which exits without scanning',
    'rather than guessing:',
    '  - every value is an ARRAY, even a single ruleset',
    '  - language keys hold registry identifiers like p/python; never a URL',
    '  - repository URLs go under third_party and nowhere else, as https:// URLs',
    '  - "all" is reserved and cannot be a language key',
    '  - one key per language, using the lowercase names from the detected list',
    '',
    'Include a language key only for languages that were actually detected. A ruleset for a',
    'language that is not present scans nothing and pads the report with coverage that did not',
    'happen.',
  ].join('\n'),
  { label: 'select', schema: SELECT_SCHEMA },
)

if (!selected || !selected.rulesetsPath) throw new Error('the select phase produced no ruleset file; no scan ran')
const c = selected.counts || {}
log(`rulesets: ${c.baseline || 0} baseline, ${c.language || 0} language, ${c.thirdParty || 0} third-party`)

phase('Scan')
// One agent, one command. Parallelism is the script's --jobs, and each exit code comes from
// the process that produced it; fanning out agents would put an LLM between semgrep and its
// own exit status.
const scanned = await agent(
  [
    'Run the Semgrep scans. One command, exactly as written:',
    '',
    `  ${SKILL_DIR}/scripts/run-scans.sh \\`,
    `    --target "${target}" \\`,
    `    --output-dir "${outputDir}" \\`,
    `    --mode ${mode} \\`,
    `    --rulesets "${selected.rulesetsPath}"${detected.pro ? ' \\\n    --pro' : ''}${jobs ? ` \\\n    --jobs ${jobs}` : ''}`,
    '',
    'Do not add rulesets, change the flags, or run semgrep yourself. The script generates every',
    'command, and --metrics=off, the --include scoping and the output-directory --exclude are',
    'its job. A scan you compose by hand drops those silently.',
    '',
    'It writes scans.json in the output directory and prints its path. Read the counts from that',
    'file with jq:',
    `  jq '.scans | length' "${outputDir}/scans.json"`,
    `  jq '.failed | length' "${outputDir}/scans.json"`,
    `  jq '.skipped | length' "${outputDir}/scans.json"`,
    '',
    'A non-zero exit means no scan succeeded. Report ok=false with the stderr, and do not retry',
    'with different arguments: the ruleset file is what produced them.',
  ].join('\n'),
  { label: 'scan', schema: SCAN_SCHEMA },
)

if (!scanned || !scanned.ok) {
  const why = (scanned && scanned.error) || 'the scan agent returned nothing'
  throw new Error(`no scan succeeded: ${why}`)
}
log(`${scanned.succeeded} scans succeeded, ${scanned.failed} failed, ${scanned.skipped} skipped`)

phase('Report')
const reported = await agent(
  [
    'Merge the scan output and write the summary.',
    '',
    `Output directory: ${outputDir}`,
    `Scan results: ${scanned.scansJson || `${outputDir}/scans.json`}`,
    `Mode: ${mode}`,
    '',
    mode === 'important-only'
      ? [
          '1. Post-filter first. Apply the "Filter All Result Files in a Directory" jq filter from',
          `   ${SKILL_DIR}/references/scan-modes.md to every result JSON in ${outputDir}/raw/.`,
          '   It writes *-important.json alongside the originals and leaves them untouched.',
          '   Every .sarif in raw/ must end up with one, because step 2 requires it.',
        ].join('\n')
      : '1. Run-all mode: no post-filter. Merge the raw output as it is.',
    '',
    '2. Merge:',
    `     uv run ${SKILL_DIR}/scripts/merge_sarif.py "${outputDir}/raw" "${outputDir}/results/results.sarif"${
      mode === 'important-only' ? ' --important' : ''
    } \\`,
    `       --scans "${scanned.scansJson || `${outputDir}/scans.json`}"`,
    '',
    '   --scans drops the output of scans recorded under .failed. A scan that died part-way may',
    '   still have written a .sarif, and without this one dead scan denies every healthy scan a',
    '   merged result: its output has no post-filter beside it, which is an error rather than an',
    '   empty filter. The excluded files are named on stdout; carry them into the report.',
    ...(mode === 'important-only'
      ? [
          '',
          '   --important is what applies the mode to the merged SARIF. Do not try to run the jq',
          '   filter from step 1 against a .sarif file: that filter reads .results[].extra.metadata,',
          '   which SARIF does not have at all, so it exits with "Cannot iterate over null" and',
          '   leaves the deliverable unfiltered. The flag matches findings across the two formats',
          '   on (rule, file, line) instead, and fails the merge if any scan has no filtered JSON.',
        ]
      : []),
    '',
    '',
    '   A non-zero exit means the merge wrote no results.sarif. Report ok=false with its stderr,',
    '   total=-1 and resultsSarif="". Do not retry it with different arguments and do not write a',
    '   summary reporting zero findings: the scans succeeded and the merge did not, and those two',
    '   read identically once a total of 0 is written down.',
    '',
    '3. Confirm the merged file is valid JSON and count the findings FROM IT:',
    `     jq '[.runs[].results[]] | length' "${outputDir}/results/results.sarif"`,
    '   Never sum the per-scan findings counts instead. One finding flagged by two rulesets is',
    '   one row in the merge and two in that sum.',
    '',
    '4. Delete the cloned rule repositories, now that nothing is reading them:',
    `     [ -n "${outputDir}" ] && rm -rf "${outputDir}/repos"`,
    '',
    '5. Write the summary as markdown. Include the finding total, a breakdown by severity and by',
    '   rule category, and where the results were written.',
    '',
    '   Read .failed and .skipped from scans.json and give them their own "Did Not Run" section',
    '   whenever either is non-empty, naming the ruleset and the reason. A run that covered four',
    '   of nine rulesets reads exactly like one that covered four of four unless you say so.',
    '   Do the same for .unscoped (languages with no --include, which ran against every file) and',
    '   .alsoShared (rulesets not repeated per language because they already ran over the whole',
    '   target — coverage is unaffected, but it explains why the ruleset and scan counts differ).',
    '',
    '   .coveredNothing gets its own section too, and matters more than the other two: those are',
    '   rulesets that opened zero files because their --include globs matched nothing. They',
    '   report 0 findings exactly like a ruleset that ran and found nothing, so leaving them out',
    '   is how a plan aimed at the wrong languages reads as a clean audit.',
    '',
    '6. Read the merge command\'s own stdout and carry two lines into the report if present:',
    '   "excluding N SARIF file(s) from failed scans" and "unparseable: N of M SARIF files".',
    '   The unparseable one is the important one. That scan is in .scans as a success with a',
    '   finding count, so its findings are missing from results.sarif and nothing in scans.json',
    '   says so — the total simply comes out lower. Name those files and say their findings are',
    '   not in the merge.',
    '',
    '7. If .excludePattern in scans.json is non-empty, give it a line too. Every scan skipped',
    '   that pattern, and semgrep matches it anywhere in the tree, so a target with its own',
    '   directory of the same name lost those files as well. It reads as clean coverage.',
  ].join('\n'),
  { label: 'report', schema: REPORT_SCHEMA },
)

if (!reported) throw new Error(`the merge phase returned nothing; raw scan output is in ${outputDir}/raw`)
// Symmetric with the scan phase. A merge that exited non-zero wrote no results.sarif, and
// returning that as a run with zero findings hides a completed scan behind a failed merge.
if (!reported.ok) {
  const why = reported.error || 'the merge agent did not say why'
  throw new Error(`the merge failed, so there is no results.sarif: ${why}. Raw scan output is in ${outputDir}/raw`)
}
log(`${reported.total} findings in ${reported.resultsSarif}`)

return {
  target,
  outputDir,
  mode,
  pro: detected.pro,
  languages: detected.languages,
  rulesetsPath: selected.rulesetsPath,
  scansJson: scanned.scansJson,
  succeeded: scanned.succeeded,
  failed: scanned.failed,
  skipped: scanned.skipped,
  resultsSarif: reported.resultsSarif,
  total: reported.total,
  report: reported.report,
}
