// Ships as /static-analysis:codeql-build. Plugin workflows are namespaced by the plugin's
// `name`, so the prefix is always `static-analysis:`; meta.name supplies the rest.
export const meta = {
  name: 'codeql-build',
  description:
    'Build a CodeQL database: detect the language, walk the build-method ladder applying fixes between rungs, and enforce the quality gate',
  whenToUse:
    'When a CodeQL database needs building and the build may not succeed first try — the ladder escalates autobuild → custom command → multi-step → no-build, diagnosing and retrying at each rung. Pass args as a JSON OBJECT: {"target": "/abs/path", "out": "/abs/path", "lang": "cpp"}. target defaults to cwd; lang is detected when omitted. Returns a status rather than asking anything, so the caller decides what to do when every method fails or the database is below the quality threshold. Database selection and analysis planning stay in the codeql SKILL.md.',
  phases: [
    { title: 'Detect', detail: 'language, build system, macOS arm64e, exclusion config' },
    { title: 'Build', detail: 'walk the method ladder, diagnosing and retrying at each rung' },
    { title: 'Assess', detail: 'quality gate, apply improvements, re-run' },
  ],
}

const SKILL_DIR = 'plugins/static-analysis/skills/codeql'

// args = { target, out, lang }. Prose is parsed too, since a caller passing a string would
// otherwise kill the run on the first line with nothing to show for it.
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
  const KEYS = ['target', 'out', 'lang']
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

// What matters is which build modes a language accepts, not whether it is interpreted. Go is
// compiled and has no `none` mode; C# and Java are compiled and do. CodeQL's own `--help` list
// omits C/C++, which does support `none` (checked on 2.25.6).
const NO_BUILD = new Set(['python', 'javascript', 'typescript', 'ruby'])
const NO_NONE_FALLBACK = new Set(['go', 'swift'])

// The ladder for a compiled language. Method 2m replaces 1 and 2 on an affected Mac: the system
// toolchain is arm64e, CodeQL's libtrace.dylib is not, and macOS SIGKILLs the process (137), so
// trying them first spends two rungs to arrive at the same failure.
function ladderFor(lang, isMacosArm64e) {
  if (NO_BUILD.has(lang)) return ['interpreted']
  const rungs = isMacosArm64e ? ['2m'] : ['1', '2']
  rungs.push('3')
  // Go and Swift reject --build-mode=none outright, so Method 4 is not a fallback for them —
  // it is a wasted cycle ending in the same "could not create a database".
  if (!NO_NONE_FALLBACK.has(lang)) rungs.push('4')
  return rungs
}

const METHODS = {
  interpreted: {
    label: 'interpreted extraction',
    detail: [
      'CodeQL extracts source directly for this language. One command, with the exclusion',
      'config written in the Detect phase:',
      '',
      '  run_logged codeql database create "$DB_NAME" \\',
      '    --language="$CODEQL_LANG" --source-root=. \\',
      '    --codescanning-config="$OUTPUT_DIR/codeql-config.yml" --overwrite',
    ].join('\n'),
  },
  1: {
    label: 'Method 1: autobuild',
    detail: [
      '  run_logged codeql database create "$DB_NAME" \\',
      '    --language="$CODEQL_LANG" --source-root=. --overwrite',
    ].join('\n'),
  },
  2: {
    label: 'Method 2: custom command',
    detail: [
      'Use the build command identified in the Detect phase.',
      '',
      '  run_logged codeql database create "$DB_NAME" \\',
      '    --language="$CODEQL_LANG" --source-root=. \\',
      '    --command="$BUILD_CMD" --overwrite',
      '',
      'Write --command="$BUILD_CMD", not --command=\'$BUILD_CMD\'. Single quotes inside a',
      'double-quoted string are literal, so the second form hands CodeQL a command starting',
      "with a ' .",
    ].join('\n'),
  },
  '2m': {
    label: 'Method 2m: macOS arm64 toolchain',
    detail: [
      `Follow the sub-method sequence in ${SKILL_DIR}/references/macos-arm64e-workaround.md:`,
      '2m-a Homebrew compiler with multi-step tracing, then 2m-b Rosetta x86_64, then 2m-c the',
      'system compiler. Stop at 2m-c: 2m-d is "ask the user", and this run reports back instead.',
    ].join('\n'),
  },
  3: {
    label: 'Method 3: multi-step build',
    detail: [
      '  run_logged codeql database init "$DB_NAME" \\',
      '    --language="$CODEQL_LANG" --source-root=. --overwrite',
      '  run_logged codeql database trace-command "$DB_NAME" -- <build step>',
      '  run_logged codeql database finalize "$DB_NAME"',
      '',
      'Every step must succeed before the next runs. Running finalize after a failed',
      'trace-command produces a database that resolves correctly and contains nothing.',
    ].join('\n'),
  },
  4: {
    label: 'Method 4: no-build fallback',
    detail: [
      '  run_logged codeql database create "$DB_NAME" \\',
      '    --language="$CODEQL_LANG" --source-root=. --build-mode=none --overwrite',
      '',
      'Last resort: no build tracing, so only source-level patterns are detected. A database',
      'built this way often fails the quality gate, and that is the honest result rather than',
      'a problem to work around.',
    ].join('\n'),
  },
}

const DETECT_SCHEMA = {
  type: 'object',
  required: ['ok', 'lang', 'target', 'outputDir', 'dbPath', 'isMacosArm64e'],
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean', description: 'false when CodeQL is missing or no language could be detected' },
    lang: { type: 'string', description: 'CodeQL language identifier, lowercase: cpp, java, python, go, …' },
    target: { type: 'string', description: 'absolute path of the source root' },
    outputDir: { type: 'string', description: 'absolute path of the created output directory' },
    dbPath: { type: 'string', description: 'absolute path the database will be built at' },
    isMacosArm64e: {
      type: 'boolean',
      description:
        'true only on an arm64 Mac whose libtrace.dylib lacks arm64e while /usr/bin/make has it — the combination macOS SIGKILLs with exit 137',
    },
    buildSystem: { type: 'string', description: 'make, cmake, gradle, maven, cargo, dotnet, or "" when none was found' },
    buildCommand: { type: 'string', description: 'the command Method 2 should pass to --command, or "" when unknown' },
    error: { type: 'string', description: 'why ok is false, else ""' },
  },
}

const BUILD_SCHEMA = {
  type: 'object',
  required: ['ok', 'resolved', 'attempts', 'error'],
  additionalProperties: false,
  properties: {
    ok: {
      type: 'boolean',
      description:
        'true only when `codeql resolve database` succeeds afterwards. The build command exiting 0 is not enough: finalize after a failed trace-command leaves a database that resolves and holds nothing.',
    },
    resolved: { type: 'boolean', description: 'the literal result of running codeql resolve database' },
    attempts: { type: 'integer', description: 'how many times this method was run, including retries after a fix' },
    fixesApplied: {
      type: 'array',
      description: 'fixes from build-fixes.md that were applied before a retry',
      items: { type: 'string' },
    },
    error: { type: 'string', description: 'the failure, with the last lines of stderr, when ok is false; else ""' },
  },
}

const ASSESS_SCHEMA = {
  type: 'object',
  required: ['exitCode', 'passed'],
  additionalProperties: false,
  properties: {
    exitCode: {
      type: 'integer',
      description:
        'final exit of check_db_quality.py. 0 pass; 1 nothing to analyse, not overridable; 3 error ratio above threshold; 4 diagnostics format changed',
    },
    passed: { type: 'boolean', description: 'true only when the final exit was 0' },
    baselineLoc: { type: 'integer', description: 'from the checker JSON, or -1 if unavailable' },
    projectFiles: { type: 'integer', description: 'from the checker JSON, or -1 if unavailable' },
    errorRatio: { type: 'number', description: 'from the checker JSON, or -1 if unavailable' },
    improvements: {
      type: 'array',
      description: 'quality improvements applied between runs of the checker',
      items: { type: 'string' },
    },
  },
}

phase('Detect')
const detected = await agent(
  [
    'Prepare a CodeQL build: resolve where it writes, confirm the tool, and profile the source.',
    '',
    `Source root: ${(input.target || '').trim() || 'the current working directory'}`,
    (input.out || '').trim() ? `Output directory: ${input.out.trim()}` : 'Output directory: choose it as described below.',
    (input.lang || '').trim() ? `Language: ${input.lang.trim()} — use it, do not re-detect.` : 'Language: detect it.',
    '',
    '1. Resolve the source root to an absolute path. Fail with ok=false if it is not a directory.',
    '2. Confirm `codeql --version` succeeds. If not, stop with ok=false — there is nothing to',
    '   profile if the database cannot be built.',
    (input.out || '').trim()
      ? '3. Use the output directory given above. mkdir -p it and resolve it absolutely.'
      : [
          '3. Pick the output directory: static_analysis_codeql_1 beside the source root,',
          '   incrementing while the name exists. mkdir -p and resolve it absolutely.',
        ].join('\n'),
    '   Set dbPath to <outputDir>/codeql.db.',
    '',
    '4. Detect the language by counting source files, and report the CodeQL identifier for it',
    '   (cpp, csharp, go, java, javascript, python, ruby, swift). CodeQL builds one language',
    `   per database. ${SKILL_DIR}/references/language-details.md has the mapping.`,
    '',
    '5. macOS arm64e check. This is the only thing that decides whether the ladder starts at',
    '   Method 1 or jumps to 2m, so run it exactly:',
    '',
    '     IS_MACOS_ARM64E=false',
    '     if [[ "$(uname -s)" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" ]]; then',
    '       LIBTRACE=$(find "$(dirname "$(command -v codeql)")" -name libtrace.dylib 2>/dev/null | head -1)',
    '       if [ -n "$LIBTRACE" ]; then',
    '         LIBTRACE_ARCHS=$(lipo -archs "$LIBTRACE" 2>/dev/null)',
    '         if [[ "$LIBTRACE_ARCHS" != *"arm64e"* ]]; then',
    '           MAKE_ARCHS=$(lipo -archs /usr/bin/make 2>/dev/null)',
    '           [[ "$MAKE_ARCHS" == *"arm64e"* ]] && IS_MACOS_ARM64E=true',
    '         fi',
    '       fi',
    '     fi',
    '',
    '6. For a compiled language, identify the build system and the command Method 2 should run:',
    '   Makefile → `make clean && make -j$(nproc)`; CMakeLists.txt → `cmake -B build && cmake',
    '   --build build`; build.gradle → `./gradlew clean build -x test`; pom.xml → `mvn clean',
    '   compile -DskipTests`; Cargo.toml → `cargo clean && cargo build`; *.sln → `dotnet clean',
    '   && dotnet build`. Also look for build.sh, compile.sh and the README.',
    '',
    '7. For python, javascript, typescript or ruby only, write the exclusion config to',
    '   <outputDir>/codeql-config.yml. Compiled languages do not support it — everything traced',
    '   is extracted — so do not write one for them.',
  ].join('\n'),
  { label: 'detect', schema: DETECT_SCHEMA },
)

if (!detected || !detected.ok) {
  const why = (detected && detected.error) || 'the detect phase returned nothing'
  return { status: 'detect-failed', error: why, dbPath: '', method: '', attempts: [] }
}
const lang = String(detected.lang || '').trim().toLowerCase()
if (!lang) return { status: 'detect-failed', error: 'no language was detected', dbPath: '', method: '', attempts: [] }
for (const [name, value] of [['target', detected.target], ['outputDir', detected.outputDir], ['dbPath', detected.dbPath]]) {
  if (!value || !String(value).startsWith('/')) {
    return { status: 'detect-failed', error: `detect returned a non-absolute ${name}: ${JSON.stringify(value)}`, dbPath: '', method: '', attempts: [] }
  }
}

const ladder = ladderFor(lang, Boolean(detected.isMacosArm64e))
log(
  `${lang} at ${detected.target}, database ${detected.dbPath}` +
    `${detected.isMacosArm64e ? ', macOS arm64e — starting at Method 2m' : ''}` +
    `${detected.buildSystem ? `, build system ${detected.buildSystem}` : ''}`,
)
log(`ladder: ${ladder.map((r) => METHODS[r].label).join(' → ')}`)

phase('Build')
// The ladder is deterministic and lives here; the diagnose-fix-retry loop for one rung lives
// inside that rung's agent, where the build output it has to read already is.
const attempts = []
let built = null
for (const rung of ladder) {
  const method = METHODS[rung]
  const result = await agent(
    [
      `Build the CodeQL database with ${method.label}.`,
      '',
      `  OUTPUT_DIR=${detected.outputDir}`,
      `  DB_NAME=${detected.dbPath}`,
      `  CODEQL_LANG=${lang}`,
      detected.buildCommand ? `  BUILD_CMD=${detected.buildCommand}` : '',
      '',
      'Each Bash call is a fresh shell, so start every block by re-establishing those and',
      `re-sourcing the helpers: . "${SKILL_DIR}/scripts/build_log.sh". Without it run_logged is`,
      '"command not found" and exits 127, which reads as a failed build rather than a missing',
      'function.',
      '',
      method.detail,
      '',
      'If it fails, diagnose before giving up. Read the build output, then consult',
      `${SKILL_DIR}/references/build-fixes.md — clean existing state, clean the build cache,`,
      'install missing dependencies, handle private registries — apply the ones the output',
      'actually points to, and retry this method once. Do not move to a different build method:',
      'the caller owns the ladder and will escalate.',
      '',
      'Then verify: `codeql resolve database -- "$DB_NAME"`. Report ok=true only when that',
      'succeeds. A build command exiting 0 is not sufficient on its own — finalize after a',
      'failed trace-command leaves a database that resolves and holds nothing, so if you ran',
      'Method 3 confirm each step succeeded too.',
      '',
      'Report the fixes you applied and the last lines of stderr on failure. A method that',
      'failed is a result to return, not a problem to work around.',
    ]
      .filter(Boolean)
      .join('\n'),
    { label: `build:${rung}`, schema: BUILD_SCHEMA },
  )

  const ok = Boolean(result && result.ok && result.resolved)
  attempts.push({
    method: method.label,
    ok,
    attempts: (result && result.attempts) || 0,
    fixesApplied: (result && result.fixesApplied) || [],
    error: ok ? '' : (result && result.error) || 'the build agent returned nothing',
  })
  log(`${method.label}: ${ok ? 'database resolves' : 'failed'}`)
  if (ok) {
    built = rung
    break
  }
}

if (!built) {
  // Every rung failed. Returned rather than asked: the caller decides whether to change the
  // build, install a toolchain, or stop.
  return {
    status: 'no-method-succeeded',
    lang,
    target: detected.target,
    outputDir: detected.outputDir,
    dbPath: '',
    method: '',
    attempts,
    error: `every build method failed for ${lang}`,
  }
}

phase('Assess')
const assessed = await agent(
  [
    'Run the quality gate on the database that was just built, and improve it if it fails.',
    '',
    `  DB_NAME=${detected.dbPath}`,
    `  OUTPUT_DIR=${detected.outputDir}`,
    '',
    `  uv run ${SKILL_DIR}/scripts/check_db_quality.py "$DB_NAME" --json`,
    '',
    'Exit codes, which do not deserve the same response:',
    '  0  passes.',
    '  1  nothing to analyse — no baseline lines of code, no project files, or unreadable.',
    '     Not a judgement call and not overridable. Report it; do not raise the threshold.',
    '  3  extractor error ratio above the threshold. A heuristic: partial C/C++ extraction over',
    '     vendored or generated code exceeds it legitimately.',
    '  4  the diagnostics format changed and the checker needs updating — the database may be fine.',
    '  (2 is argparse\'s usage error and never one of our verdicts.)',
    '',
    'On exit 3 only, try the improvements in',
    `${SKILL_DIR}/references/quality-assessment.md — adjust the source root, force a clean`,
    'rebuild if the build was cached, install type stubs, set extractor options — then re-run',
    'the checker once and report the final exit code. Report every improvement you applied.',
    '',
    'Do not raise --max-error-ratio to make the gate pass. Whether the remaining errors are',
    'confined to code that does not need analysing is the caller\'s call, not yours; report the',
    'ratio and let them decide.',
    '',
    'Read baseline_loc, project_files and error_ratio from the checker\'s JSON. Use -1 for any',
    'the JSON did not carry rather than guessing a number.',
  ].join('\n'),
  { label: 'assess', schema: ASSESS_SCHEMA },
)

const passed = Boolean(assessed && assessed.passed && assessed.exitCode === 0)
log(
  passed
    ? `quality gate passed (${METHODS[built].label})`
    : `quality gate failed with exit ${(assessed && assessed.exitCode) ?? '?'} — the database exists but is below threshold`,
)

return {
  // Two success statuses, because a database that built but did not pass is a real outcome the
  // caller has to decide about rather than a failure to hide or a pass to claim.
  status: passed ? 'built' : 'built-below-threshold',
  lang,
  target: detected.target,
  outputDir: detected.outputDir,
  dbPath: detected.dbPath,
  method: METHODS[built].label,
  attempts,
  quality: assessed || null,
  logFile: `${detected.outputDir}/build.log`,
}
