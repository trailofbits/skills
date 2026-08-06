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

// args = { target, out, mode, jobs }, all optional. Prose is parsed too (`target: /x; mode:
// run-all`), since a caller passing a string would otherwise kill the run on the first line.
const parseArgs = (raw) => {
  if (!raw) return {}
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string') return {}
  const text = raw.trim()
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text)
    } catch {
      // Fall through to key: value parsing rather than dying on a malformed brace.
    }
  }
  const KEYS = ['target', 'out', 'mode', 'jobs']
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
  return out
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

const DETECT_SCHEMA = {
  type: 'object',
  required: ['target', 'outputDir', 'pro', 'languages'],
  additionalProperties: false,
  properties: {
    target: { type: 'string', description: 'absolute path that was scanned for languages' },
    outputDir: { type: 'string', description: 'absolute path of the created output directory' },
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

const REPORT_SCHEMA = {
  type: 'object',
  required: ['resultsSarif', 'total', 'report'],
  additionalProperties: false,
  properties: {
    resultsSarif: { type: 'string', description: 'absolute path of the merged SARIF' },
    total: { type: 'integer', description: 'finding count read from the merged SARIF, never summed from per-scan counts' },
    report: { type: 'string', description: 'the markdown summary to show the user' },
  },
}

// Both paths read these, so a ruleset added to rulesets.md reaches the workflow too.
const SKILL_DIR = 'plugins/static-analysis/skills/semgrep'

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
    '3. Confirm semgrep is installed (`semgrep --version`). If it is not, stop and say so —',
    '   there is no point profiling a codebase you cannot scan.',
    '',
    '4. Check Pro. Keep stderr: "OSS only" has several causes (logged out, no subscription,',
    '   registry blocked) and the run downgrades silently for all of them.',
    '     if PRO_ERR=$(semgrep --pro --validate --metrics=off --config p/default 2>&1); then',
    '       echo "Pro available"; else echo "OSS only"; printf \'%s\' "$PRO_ERR" | tail -n 3; fi',
    '   --metrics=off matters here too: this is the first semgrep call of the run and it resolves',
    '   p/default against the registry, so without it an audit phones home before scanning.',
    '',
    '5. Detect languages by counting files. Report the count that justified each category, since',
    '   a category with one file is worth knowing about before its rulesets run. Cover at least:',
    '   python, javascript, typescript, go, ruby, java, php, c, cpp, rust, docker, terraform,',
    '   kubernetes. Use lowercase category names.',
    '',
    '6. Read the framework markers that exist — package.json, pyproject.toml, Gemfile, go.mod,',
    '   Cargo.toml, pom.xml — and name the frameworks you find (django, flask, react, express,',
    '   nextjs, spring, …). These select extra rulesets in the next phase.',
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

const langNames = (detected.languages || []).map((l) => l.name).filter(Boolean)
log(
  `target ${target}, output ${outputDir}, ${detected.pro ? 'Pro' : 'OSS'}, ` +
    `${langNames.length ? langNames.join(', ') : 'no languages detected'}` +
    `${(detected.frameworks || []).length ? ` (${detected.frameworks.join(', ')})` : ''}`,
)
if (!detected.pro && detected.proReason) log(`Pro unavailable: ${detected.proReason}`)

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
          '   Then apply the same jq filter to the merged SARIF after step 2, because the JSON',
          '   post-filter does not touch the .sarif files the merge reads.',
        ].join('\n')
      : '1. Run-all mode: no post-filter. Merge the raw output as it is.',
    '',
    '2. Merge:',
    `     uv run ${SKILL_DIR}/scripts/merge_sarif.py "${outputDir}/raw" "${outputDir}/results/results.sarif"`,
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
  ].join('\n'),
  { label: 'report', schema: REPORT_SCHEMA },
)

if (!reported) throw new Error(`the merge phase returned nothing; raw scan output is in ${outputDir}/raw`)
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
