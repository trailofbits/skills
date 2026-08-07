# Build Database Workflow

Create high-quality CodeQL databases by trying build methods in sequence until one produces good results.

## Overview

What matters is which build modes a language accepts, not whether it is interpreted.
Go is compiled but has no `none` mode; C# and Java are compiled and do. Confirm against
your own CLI with `codeql database create --help`, and note its `none` list is
incomplete — it omits C/C++ and Rust, both of which do support `none` (2.25.6).

### No build needed (Python, JavaScript/TypeScript, Ruby)
- CodeQL extracts source directly
- **Exclusion config supported** — use `--codescanning-config` to skip irrelevant files

### Build required, no fallback (Go, Swift)
- `--build-mode=none` is **rejected**: *"Go does not support the none build mode. Please
  try using one of the following build modes instead: autobuild, manual."*
- Autobuild usually suffices for Go when the toolchain is present and the module builds.
  If it fails there is no no-build escape — fix the build or stop.
- Skip Method 4 for these languages.

### Build required, `none` available as a fallback (C/C++, Java/Kotlin, C#, Rust)
- **Build required for complete extraction** — CodeQL must trace the compilation
- **Exclusion config NOT supported** — all traced code is extracted
- `--build-mode=none` works but produces partial analysis. Method 4, last resort.
- Try build methods in order until one succeeds:
  1. **Autobuild** — CodeQL auto-detects and runs the build
  2. **Custom Command** — Explicit build command for the detected build system
  2m. **macOS arm64 Toolchain** — Homebrew compiler + multi-step tracing (Apple Silicon workaround)
  3. **Multi-step** — Fine-grained control with init → trace-command → finalize
  4. **No-build fallback** — `--build-mode=none` (partial analysis, last resort)

> **macOS Apple Silicon:** On arm64 Macs, system tools (`/usr/bin/make`, `/usr/bin/clang`, `/usr/bin/ar`) are `arm64e` but CodeQL's `libtrace.dylib` only has `arm64`. macOS kills `arm64e` processes with a non-`arm64e` injected dylib (SIGKILL, exit 137). Step 2a detects this and routes to Method 2m.

---

## Build Log

`$OUTPUT_DIR` arrives from the parent skill, resolved once at invocation. Every file this
workflow writes goes inside it. Source the log helpers before any build step, and in any
reference doc that uses `run_logged`:

```bash
DB_NAME="$OUTPUT_DIR/codeql.db"
. "{baseDir}/scripts/build_log.sh" || exit 1
log_step "CodeQL database build — $DB_NAME"
```

That provides `log_step`, `log_cmd`, `log_result`, and `run_logged`; defaults `LOG_FILE` to
`$OUTPUT_DIR/build.log` and stops if it is not writable; and sets `pipefail` so a command's
exit status survives being piped to `tee`. It deliberately does not set `-e`: the method
ladder below has to survive each failed method to reach the next one.

> **Every block below that uses a helper repeats the source line.** A function defined in an
> earlier Bash call is gone by the next one, and `run_logged` then exits 127, which the ladder
> reads as a failed build method. Set `DB_NAME` and `CODEQL_LANG` in the block as well.
> See [Each Bash call is a fresh shell](../SKILL.md#each-bash-call-is-a-fresh-shell).

**What to log:** Detected language/build system, each build attempt with exact command, fix attempts and outcomes, quality assessment results, final successful command.

---

## Step 1: Detect Language and Configure

**Entry:** CodeQL CLI installed and on PATH (`codeql --version` succeeds)
**Exit:** `CODEQL_LANG` variable set to a valid CodeQL language identifier; exclusion config created (interpreted) or skipped (compiled)

### 1a. Detect Language

```bash
# fd is not in the Quick Start preflight. Without this fallback a machine that lacks it
# prints an empty histogram — fd's error goes to stderr and the rest of the pipeline
# succeeds — and the language gets picked by guess.
if command -v fd >/dev/null 2>&1; then
  fd -t f -e py -e js -e ts -e go -e rb -e java -e c -e cpp -e h -e hpp -e rs -e cs
else
  find . -type f \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.go' \
    -o -name '*.rb' -o -name '*.java' -o -name '*.c' -o -name '*.cpp' -o -name '*.h' \
    -o -name '*.hpp' -o -name '*.rs' -o -name '*.cs' \) -not -path './.git/*'
fi | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -5

ls -la Makefile CMakeLists.txt build.gradle pom.xml Cargo.toml *.sln 2>/dev/null || true
```

| Language | `--language=` | Build needed | `--build-mode=none` |
|----------|---------------|-------------|---------------------|
| Python | `python` | No | Supported |
| JavaScript/TypeScript | `javascript` | No | Supported |
| Ruby | `ruby` | No | Supported |
| Go | `go` | **Yes** | **Rejected** — autobuild or manual only |
| Swift | `swift` | **Yes** (macOS) | **Rejected** |
| Java/Kotlin | `java` | Yes | Supported (partial analysis) |
| C# | `csharp` | Yes | Supported (partial analysis) |
| C/C++ | `cpp` | Yes | Supported (partial analysis) |
| Rust | `rust` | Yes | Supported (partial analysis) — omitted from `--help`, like C/C++ |

Verified against CodeQL 2.25.6. Re-check with `codeql database create --help` if your
version differs; the supported modes have changed between releases.

### 1b. Create Exclusion Config (Interpreted Languages Only)

> **Skip for compiled languages** — exclusion config is not supported when build tracing is required.

Scan for irrelevant directories and create `$OUTPUT_DIR/codeql-config.yml` with `paths-ignore` entries for `node_modules`, `vendor`, `venv`, third-party code, and generated/minified files.

---

## Step 2: Build Database

**Entry:** Step 1 complete (`CODEQL_LANG` set, `DB_NAME` assigned, log file initialized)
**Exit:** `codeql resolve database -- "$DB_NAME"` succeeds (database exists and is valid)

### For Interpreted Languages

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Building database for interpreted language: <LANG>"
run_logged codeql database create "$DB_NAME" \
  --language="$CODEQL_LANG" \
  --source-root=. \
  --codescanning-config="$OUTPUT_DIR/codeql-config.yml" \
  --overwrite
```

**Skip to Step 4 after success.**

---

### For Compiled Languages

#### Step 2a: macOS arm64e Detection (C/C++ primarily)

```bash
IS_MACOS_ARM64E=false
if [[ "$(uname -s)" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" ]]; then
  LIBTRACE=$(find "$(dirname "$(command -v codeql)")" -name libtrace.dylib 2>/dev/null | head -1)
  if [ -n "$LIBTRACE" ]; then
    LIBTRACE_ARCHS=$(lipo -archs "$LIBTRACE" 2>/dev/null)
    if [[ "$LIBTRACE_ARCHS" != *"arm64e"* ]]; then
      MAKE_ARCHS=$(lipo -archs /usr/bin/make 2>/dev/null)
      [[ "$MAKE_ARCHS" == *"arm64e"* ]] && IS_MACOS_ARM64E=true
    fi
  fi
fi
```

**If `IS_MACOS_ARM64E=true`:** Skip Methods 1 and 2 — go directly to Method 2m.

---

Try build methods in sequence until one succeeds:

#### Method 1: Autobuild

> **Skip if `IS_MACOS_ARM64E=true`.**

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "METHOD 1: Autobuild"
run_logged codeql database create "$DB_NAME" \
  --language="$CODEQL_LANG" --source-root=. --overwrite
```

`run_logged` returns the build's exit status. Check it before moving on. A non-zero
status means this method failed and the next one should be tried.

#### Method 2: Custom Command

> **Skip if `IS_MACOS_ARM64E=true`.**

Detect build system and use explicit command:

| Build System | Detection | Command |
|--------------|-----------|---------|
| Make | `Makefile` | `make clean && make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"` |
| CMake | `CMakeLists.txt` | `cmake -B build && cmake --build build` |
| Gradle | `build.gradle` | `./gradlew clean build -x test` |
| Maven | `pom.xml` | `mvn clean compile -DskipTests` |
| Cargo | `Cargo.toml` | `cargo clean && cargo build` |
| .NET | `*.sln` | `dotnet clean && dotnet build` |

Also check for project-specific build scripts (`build.sh`, `compile.sh`) and README instructions.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "METHOD 2: Custom command"
run_logged codeql database create "$DB_NAME" \
  --language="$CODEQL_LANG" \
  --source-root=. \
  --command="$BUILD_CMD" \
  --overwrite
```

Use `--command="$BUILD_CMD"`, not `--command='$BUILD_CMD'`. Single quotes inside a
double-quoted string are literal characters, so the second form passes CodeQL a command
that starts with a `'`.

#### Method 2m: macOS arm64 Toolchain (Apple Silicon workaround)

> **Use when `IS_MACOS_ARM64E=true`.** Replaces Methods 1 and 2 on affected systems.

See [macos-arm64e-workaround.md](../references/macos-arm64e-workaround.md) for the full sub-method sequence (2m-a through 2m-d): Homebrew compiler with multi-step tracing → Rosetta x86_64 → system compiler verification → ask user.

#### Method 3: Multi-step Build

For complex builds needing fine-grained control:

> **On macOS with `IS_MACOS_ARM64E=true`:** Only trace arm64 Homebrew binaries. Do NOT trace system tools.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "METHOD 3: Multi-step build"

# Each step gates the next. `finalize` after a failed `trace-command` produces a database
# that resolves correctly and contains nothing, so the rung reports success.
if ! run_logged codeql database init "$DB_NAME" \
  --language="$CODEQL_LANG" --source-root=. --overwrite; then
  log_result "FAILED (init)"
elif ! run_logged codeql database trace-command "$DB_NAME" -- <build step 1>; then
  log_result "FAILED (build step 1)"
elif ! run_logged codeql database trace-command "$DB_NAME" -- <build step 2>; then
  log_result "FAILED (build step 2)"
elif ! run_logged codeql database finalize "$DB_NAME"; then
  log_result "FAILED (finalize)"
else
  log_result "SUCCESS (multi-step)"
fi
```

Add one `elif` per build step. A method that stops early has failed: move to Method 4.

#### Method 4: No-Build Fallback (Last Resort)

> **WARNING:** Creates a database without build tracing. Only source-level patterns detected.
>
> **Not available for Go or Swift.** They reject `--build-mode=none` outright, so there is
> no fallback: fix the build, or report that a database could not be created. Do not burn
> a cycle attempting this for those languages.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "METHOD 4: No-build fallback (partial analysis)"
run_logged codeql database create "$DB_NAME" \
  --language="$CODEQL_LANG" --source-root=. --build-mode=none --overwrite
```

Databases built this way often fail `check_db_quality.py` in Step 4. That is the expected
result: without build tracing there may be no analysable source, and the analysis would
report zero findings.

---

## Step 3: Apply Fixes (if build failed)

**Entry:** Step 2 build method failed (non-zero exit or `codeql resolve database` fails)
**Exit:** Fix applied and current build method retried; either succeeds (go to Step 4) or all fixes exhausted (try next build method in Step 2)

Try fixes in order, then retry current build method. See [build-fixes.md](../references/build-fixes.md) for the full fix catalog: clean state, clean build cache, install dependencies, handle private registries.

---

## Steps 4-5: Assess and Improve Quality

**Entry:** Database exists and `codeql resolve database` succeeds
**Exit (Step 4):** `check_db_quality.py` exits zero
**Exit (Step 5):** Quality improvements applied and the check re-run, OR user accepts a database that fails it

Run the gate first:

```bash
uv run {baseDir}/scripts/check_db_quality.py "$DB_NAME"
```

**A non-zero exit means do not proceed to analysis.** A database in that state analyses
without error and reports zero findings, which is the same output a clean codebase
produces. The two failure exits call for different responses:

Exit 1 is not a judgement call — go to Step 5 and fix the build. Exit 3 is, and
[quality-assessment.md](../references/quality-assessment.md) has the table for it and for
exits 2 and 4.

If it fails, go to [quality-assessment.md](../references/quality-assessment.md) for the
metric breakdown and the improvement steps, then re-run the gate. If it still fails after
those, present the metrics to the user and let them decide rather than continuing silently.

---

## Exit Conditions

**Success:** Quality assessment shows GOOD or user accepts current state.

**Failure (all methods exhausted):**
```
AskUserQuestion: "All build methods failed. Options:"
  1. "Accept current state" (if any database exists)
  2. "I'll fix the build manually and retry"
  3. "Abort"
```

---

## Final Report

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

echo "=== Build Complete ===" >> "$LOG_FILE"
echo "Finished: $(date -Iseconds)" >> "$LOG_FILE"
echo "Final database: $DB_NAME" >> "$LOG_FILE"
echo "Successful method: <METHOD>" >> "$LOG_FILE"
codeql resolve database -- "$DB_NAME" >> "$LOG_FILE" 2>&1
```

Report to user:
```
## Database Build Complete

**Output directory:** $OUTPUT_DIR
**Database:** $DB_NAME
**Language:** <LANG>
**Build method:** autobuild | custom | multi-step
**Files extracted:** <COUNT>

### Quality:
- Errors: <N>
- Coverage: <good/partial/poor>

### Build Log:
See `$OUTPUT_DIR/build.log` for complete details.

**Final command used:** <EXACT_COMMAND>
**Ready for analysis.**
```
