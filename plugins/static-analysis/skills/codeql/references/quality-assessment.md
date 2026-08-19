# Quality Assessment

How to assess and improve CodeQL database quality after a successful build.

## Collect Metrics

One call produces every metric and enforces the thresholds. Nothing else recomputes any of
them: a second hand-written pipeline drifts from the script and logs a contradicting number,
which is how this file came to report 202 project files where the script said 2.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Assessing database quality"

# Capture the status into a variable. Inside `if ! cmd; then`, `$?` is the *negated*
# status and always reads 0, so the log would record every failure as a success.
QUALITY_JSON=$(uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME" --format=json)
QUALITY_STATUS=$?
if [ "$QUALITY_STATUS" -ne 0 ]; then
  log_result "Quality gate failed (exit $QUALITY_STATUS) — see Enforce the Thresholds below"
  exit "$QUALITY_STATUS"
fi

printf '%s' "$QUALITY_JSON" | jq -r '
  "Baseline LoC: \(.baseline_loc)",
  "Project source files: \(.project_files)",
  "Total archive files: \(.archive_files) (system headers included for compiled languages)",
  "Extractor errors: \(.extractor_errors) (\(.error_ratio)%)",
  "Finalised: \(.finalised)"' | tee -a "$LOG_FILE"

# Not derived from the database, so the script cannot report it.
DIAG_TEXT=$(codeql database export-diagnostics --format=text -- "$DB_NAME" 2>/dev/null || true)
if [ -n "$DIAG_TEXT" ]; then
  echo "Diagnostics: $DIAG_TEXT"
fi
```

## Compare Against Expected Source

The one number the checker cannot produce: how many source files the working tree holds.
Compare it against `.project_files`, never against `.archive_files` — for C/C++ the archive
runs 10-20x larger because it carries the SDK headers (690 against 473 on a real mbedtls
database).

```bash
# `fd` is not in the Quick Start preflight, and a missing fd exits non-zero into `wc -l`,
# which prints 0 — so this would read as "extraction met expectations" on a machine that
# simply lacks the tool.
if command -v fd >/dev/null 2>&1; then
  EXPECTED=$(fd -t f -e c -e cpp -e h -e hpp -e java -e kt -e py -e js -e ts \
    --exclude 'codeql_*.db' --exclude node_modules --exclude vendor --exclude .git . \
    | wc -l)
else
  EXPECTED=$(find . -type f \( -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \
    -o -name '*.java' -o -name '*.kt' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \) \
    -not -path './.git/*' -not -path './node_modules/*' -not -path './vendor/*' \
    -not -path './codeql_*.db/*' | wc -l)
fi
echo "Expected source files: $EXPECTED"
```

## Enforce the Thresholds

The numbers above are only useful if something compares them to a threshold, which the
call in Collect Metrics already does. Its two failure exits are not equivalent:

| Exit | Meaning | What to do |
|------|---------|------------|
| `1` | Nothing to analyse — no baseline LoC, or no project files in the source archive | Stop. Fix the build; do not analyse. Not overridable |
| `3` | Extractor error ratio above 5% | Judgement call. See below |
| `4` | Diagnostics format changed — the checker needs updating | Report it; the database itself may be fine |

Exit `2` is argparse's usage error, so a mistyped flag can never be mistaken for a
threshold decision.

Zero project files means build tracing captured nothing. A database in that state still
analyses without error and reports zero findings, so exit 1 has to stop the run rather
than leave it to be noticed later.

Exit 3 is a heuristic, and partial C/C++ extraction over vendored dependencies or
generated code exceeds it legitimately. Look at which files failed before deciding: if
the errors are confined to code that does not need analysing, re-run with a raised
threshold and record the reason in the log.

The log line goes inside the `if`. After it, a re-run that still fails writes "Raised
threshold to 15%" as though the override took, and the block exits 0 — `log_result`'s status.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

if uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME" --max-error-ratio 15; then
  log_result "Raised error-ratio threshold to 15%: failures are all in third_party/, not project source"
else
  log_result "Still failing at a 15% error ratio — the failures are not confined to third_party/"
  exit 1
fi
```

## Quality Criteria

Every metric below comes from the single call in Collect Metrics. The gate already fails on
the first three; the rest are for reading the result.

| Metric | JSON key | Good | Poor |
|--------|----------|------|------|
| Baseline LoC | `.baseline_loc` | > 0, proportional to project size | 0 or far below expected |
| Project source files | `.project_files` | Close to the expected count | 0 or < 50% of expected |
| Extractor errors | `.error_ratio` | < 5% of project files | > 5% |
| Total archive files | `.archive_files` | 10-20x `.project_files` for C/C++, ≈ equal for interpreted | equal to `.project_files` for C/C++ (no toolchain traced) |
| Finalised | `.finalised` | `true` | `false` or absent (interrupted build) |
| "No source code seen" | build log | Absent | Present (cached build, compiled languages) |

A small number of extractor errors is normal. Baseline LoC of 0, or an archive with no
project files, means the database is empty: a cached build for a compiled language, or the
wrong `--source-root`.

---

## Improve Quality (if poor)

Try these improvements, re-assess after each. **Log all improvements:**

### 1. Adjust source root

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Quality improvement: adjust source root"
NEW_ROOT="./src"  # or detected subdirectory
# For interpreted: add --codescanning-config=codeql-config.yml
# For compiled: omit config flag
run_logged codeql database create "$DB_NAME" \
  --language="$CODEQL_LANG" --source-root="$NEW_ROOT" --overwrite
log_result "Changed source-root to: $NEW_ROOT"
```

### 2. Fix "no source code seen" (cached build - compiled languages only)

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Quality improvement: force rebuild (cached build detected)"
# The rebuild is only worth running if the clean succeeded. Against a still-cached tree it
# re-extracts the same empty database, and the log would record that as a fix.
if make clean; then
  run_logged codeql database create "$DB_NAME" --language="$CODEQL_LANG" --overwrite
  log_result "Forced clean rebuild"
else
  log_result "SKIPPED: make clean failed, so the build is still cached"
fi
```

### 3. Install type stubs / dependencies

> **Note:** These install into the *target project's* environment to improve CodeQL extraction quality.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Quality improvement: install type stubs/additional deps"

# Python type stubs — install into target project's environment
STUBS_INSTALLED=""
for stub in types-requests types-PyYAML types-redis; do
  if pip install "$stub" 2>/dev/null; then
    STUBS_INSTALLED="$STUBS_INSTALLED $stub"
  fi
done
log_result "Installed type stubs:$STUBS_INSTALLED"

# Additional project dependencies
run_logged pip install -e . || log_result "WARNING: pip install -e . failed — extraction may stay incomplete"
```

### 4. Adjust extractor options

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Quality improvement: adjust extractor options"

# C/C++: Include headers
export CODEQL_EXTRACTOR_CPP_OPTION_TRAP_HEADERS=true
log_result "Set CODEQL_EXTRACTOR_CPP_OPTION_TRAP_HEADERS=true"

# Java: Specific JDK version
export CODEQL_EXTRACTOR_JAVA_OPTION_JDK_VERSION=17
log_result "Set CODEQL_EXTRACTOR_JAVA_OPTION_JDK_VERSION=17"

# Then rebuild with current method
```

**After each improvement:** Re-assess quality. If no improvement possible, move to next build method.
