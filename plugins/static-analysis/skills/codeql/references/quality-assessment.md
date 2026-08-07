# Quality Assessment

How to assess and improve CodeQL database quality after a successful build.

## Collect Metrics

```bash
# Each Bash call is a fresh shell, so the helpers have to be re-sourced here even though an
# earlier block already did it. Without this, log_step and log_result are "command not found";
# there is no `set -e` in this block, so it runs on and the build log records nothing —
# including, further down, the reason the quality gate failed.
. "{baseDir}/scripts/build_log.sh"

log_step "Assessing database quality"

# 1. Total archive file count. The only metric the checker does not report: it counts
#    project source under the recorded source root, which for a compiled language is a
#    fraction of the archive.
SRC_FILE_COUNT=$(unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null | wc -l)
echo "Files in source archive: $SRC_FILE_COUNT"

# 2. Quality gate and the metrics it derives, in one call. Exit 1 means nothing to
#    analyse, 3 the error ratio was exceeded, 4 a format change; see "Enforce the
#    Thresholds".
#    Everything downstream reads $QUALITY_JSON rather than recomputing — a second
#    hand-written pipeline drifts from the script and logs a contradicting number.
#    Capture the status into a variable: inside `if ! cmd; then`, `$?` is the *negated*
#    status and always reads 0, so the log would record every failure as a success.
QUALITY_JSON=$(uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME" --format=json)
QUALITY_STATUS=$?
if [ "$QUALITY_STATUS" -ne 0 ]; then
  log_result "Quality gate failed (exit $QUALITY_STATUS) — see Enforce the Thresholds below"
  exit "$QUALITY_STATUS"
fi
PROJECT_SRC_COUNT=$(printf '%s' "$QUALITY_JSON" | jq -r '.project_files')
DB_LOC=$(printf '%s' "$QUALITY_JSON" | jq -r '.baseline_loc')
EXTRACTOR_ERRORS=$(printf '%s' "$QUALITY_JSON" | jq -r '.extractor_errors')
ERROR_RATIO=$(printf '%s' "$QUALITY_JSON" | jq -r '.error_ratio')
echo "Project files: $PROJECT_SRC_COUNT, baseline LoC: $DB_LOC, extractor errors: $EXTRACTOR_ERRORS (${ERROR_RATIO}%)"

# 3. Export diagnostics summary (experimental but useful)
DIAG_TEXT=$(codeql database export-diagnostics --format=text -- "$DB_NAME" 2>/dev/null || true)
if [ -n "$DIAG_TEXT" ]; then
  echo "Diagnostics: $DIAG_TEXT"
fi

# 4. Check database is finalized
FINALIZED=$(grep '^finalised:' "$DB_NAME/codeql-database.yml" 2>/dev/null \
  | awk '{print $2}')
echo "Finalized: $FINALIZED"
```

## Compare Against Expected Source

Estimate the expected source file count from the working directory and compare.

> **Compiled languages (C/C++, Java, C#):** The source archive (`src.zip`) includes system headers and SDK files alongside project source files. For C/C++, this can inflate the archive count 10-20x (e.g., 111 archive files for 5 project source files). Compare against **project-relative files only** by filtering the archive listing.

```bash
# Count source files in the project. `fd` is not in the Quick Start preflight, and a
# missing fd exits non-zero into `wc -l`, which prints 0 — so the comparison below would
# read as "extraction met expectations" on a machine that simply lacks the tool.
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

# PROJECT_SRC_COUNT and DB_LOC come from check_db_quality.py above. Do not recount here:
# the script counts files under the source root recorded in codeql-database.yml, and the
# `grep -v '^(Library/|usr/|System/…)'` this block used to run is a macOS-shaped guess
# that scores a Linux toolchain under nix/store/ as project source — 202 files where the
# script says 2.
echo "Project files in source archive: $PROJECT_SRC_COUNT"
echo "Total files in source archive: $SRC_FILE_COUNT (includes system headers for compiled langs)"
echo "Baseline LoC: $DB_LOC"
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

The log line is inside the `if`, not after it. Unguarded, a re-run that still fails the raised
threshold writes "Raised error-ratio threshold to 15%" into the build log as though the override
took, and the block's own exit status becomes `log_result`'s 0 — a decision recorded as made
because the command that refused it ran first.

```bash
. "{baseDir}/scripts/build_log.sh"

if uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME" --max-error-ratio 15; then
  log_result "Raised error-ratio threshold to 15%: failures are all in third_party/, not project source"
else
  log_result "Still failing at a 15% error ratio — the failures are not confined to third_party/"
  exit 1
fi
```

## Log Assessment

This block runs in its own shell, so re-source the helpers and re-read the metrics rather
than expecting them to survive from Collect Metrics. Unset, they expand to empty and the log
records `Baseline LoC:` with no number.

```bash
. "{baseDir}/scripts/build_log.sh"
QUALITY_JSON=$(uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME" --format=json)
DB_LOC=$(printf '%s' "$QUALITY_JSON" | jq -r '.baseline_loc')
PROJECT_SRC_COUNT=$(printf '%s' "$QUALITY_JSON" | jq -r '.project_files')
SRC_FILE_COUNT=$(unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null | wc -l)
FINALIZED=$(grep '^finalised:' "$DB_NAME/codeql-database.yml" 2>/dev/null | awk '{print $2}')

log_step "Quality assessment results"
log_result "Baseline LoC: $DB_LOC"
log_result "Project source files: $PROJECT_SRC_COUNT"
log_result "Total archive files: $SRC_FILE_COUNT (includes system headers for compiled langs)"
# Extractor errors are reported by check_db_quality.py above, which is the only
# place that counts them correctly.
log_result "Finalized: $FINALIZED"

# Sample extracted project files (exclude system paths)
unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null \
  | grep -v -E '^(Library/|usr/|System/|opt/|Applications/)' \
  | head -20 >> "$LOG_FILE"
```

## Quality Criteria

| Metric | Source | Good | Poor |
|--------|--------|------|------|
| Baseline LoC | `check_db_quality.py` (`.baseline_loc`) | > 0, proportional to project size | 0 or far below expected |
| Project source files | `src.zip` (filtered) | Close to expected source file count | 0 or < 50% of expected |
| Extractor errors | `diagnostic/extractors/*.jsonl` | 0 or < 5% of project files | > 5% of project files |
| Finalized | `codeql-database.yml` | `true` | `false` (incomplete build) |
| Key directories | `src.zip` listing | Application code directories present | Missing `src/main`, `lib/`, `app/` etc. |
| "No source code seen" | build log | Absent | Present (cached build — compiled languages) |

**Interpreting archive file counts for compiled languages:** C/C++ databases include system headers (e.g., `<stdio.h>`, SDK headers) in `src.zip`. A project with 5 source files may have 100+ files in the archive. Always filter to project-relative paths when comparing against expected counts. Use `baselineLinesOfCode` as the primary quality indicator.

**Interpreting baseline LoC:** A small number of extractor errors is normal and does not significantly impact analysis. However, if `baselineLinesOfCode` is 0 or the source archive contains no files, the database is empty — likely a cached build (compiled languages) or wrong `--source-root`.

---

## Improve Quality (if poor)

Try these improvements, re-assess after each. **Log all improvements:**

### 1. Adjust source root

```bash
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
. "{baseDir}/scripts/build_log.sh"

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
