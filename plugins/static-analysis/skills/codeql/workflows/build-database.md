# Build Database Workflow

Create high-quality CodeQL databases by trying build methods in sequence until one produces good results.

## Task System

Create these tasks on workflow start:

```
TaskCreate: "Detect language and configure" (Step 1)
TaskCreate: "Build database" (Step 2) - blockedBy: Step 1
TaskCreate: "Apply fixes if needed" (Step 3) - blockedBy: Step 2
TaskCreate: "Assess quality" (Step 4) - blockedBy: Step 3
TaskCreate: "Improve quality if needed" (Step 5) - blockedBy: Step 4
TaskCreate: "Generate final report" (Step 6) - blockedBy: Step 5
```

---

## Overview

Database creation differs by language type:

### Interpreted Languages (Python, JavaScript, Go, Ruby)
- **No build required** - CodeQL extracts source directly
- **Exclusion config supported** - Use `--codescanning-config` to skip irrelevant files

### Compiled Languages (C/C++, Java, C#, Rust, Swift)
- **Build required** - CodeQL must trace the compilation
- **Exclusion config NOT supported** - All compiled code must be traced
- Try build methods in order until one succeeds:
  1. **Autobuild** - CodeQL auto-detects and runs the build
  2. **Custom Command** - Explicit build command for the detected build system
  3. **Multi-step** - Fine-grained control with init → trace-command → finalize
  4. **No-build fallback** - `--build-mode=none` (partial analysis, last resort)

---

## Database Naming

Generate a unique sequential database name to avoid overwriting previous databases:

```bash
# Find next available database number
get_next_db_name() {
  local prefix="${1:-codeql}"
  local max=0
  for db in ${prefix}_*.db; do
    if [[ -d "$db" ]]; then
      num="${db#${prefix}_}"
      num="${num%.db}"
      if [[ "$num" =~ ^[0-9]+$ ]] && (( num > max )); then
        max=$num
      fi
    fi
  done
  echo "${prefix}_$((max + 1)).db"
}

DB_NAME=$(get_next_db_name)
echo "Database name: $DB_NAME"
```

Use `$DB_NAME` in all commands below.

---

## Build Log

Maintain a detailed log file throughout the workflow. Log every significant action.

**Initialize at start:**
```bash
LOG_FILE="${DB_NAME%.db}-build.log"
echo "=== CodeQL Database Build Log ===" > "$LOG_FILE"
echo "Started: $(date -Iseconds)" >> "$LOG_FILE"
echo "Working directory: $(pwd)" >> "$LOG_FILE"
echo "Database: $DB_NAME" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"
```

**Log helper function:**
```bash
log_step() {
  echo "[$(date -Iseconds)] $1" >> "$LOG_FILE"
}

log_cmd() {
  echo "[$(date -Iseconds)] COMMAND: $1" >> "$LOG_FILE"
}

log_result() {
  echo "[$(date -Iseconds)] RESULT: $1" >> "$LOG_FILE"
  echo "" >> "$LOG_FILE"
}
```

**What to log:**
- Detected language and build system
- Each build attempt with exact command
- Fix attempts and their outcomes:
  - Cache/artifacts cleaned
  - Dependencies installed (package names, versions)
  - Downloaded JARs, npm packages, Python wheels
  - Registry authentication configured
- Quality improvements applied:
  - Source root adjustments
  - Extractor options set
  - Type stubs installed
- Quality assessment results (file counts, errors)
- Final successful command with all environment variables

---

## Step 1: Detect Language and Configure

### 1a. Detect Language

```bash
# Detect primary language by file count
fd -t f -e py -e js -e ts -e go -e rb -e java -e c -e cpp -e h -e hpp -e rs -e cs | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn | head -5

# Check for build files (compiled languages)
ls -la Makefile CMakeLists.txt build.gradle pom.xml Cargo.toml *.sln 2>/dev/null || true

# Check for existing CodeQL database
ls -la "$DB_NAME" 2>/dev/null && echo "WARNING: existing database found"
```

| Language | `--language=` | Type |
|----------|---------------|------|
| Python | `python` | Interpreted |
| JavaScript/TypeScript | `javascript` | Interpreted |
| Go | `go` | Interpreted |
| Ruby | `ruby` | Interpreted |
| Java/Kotlin | `java` | Compiled |
| C/C++ | `cpp` | Compiled |
| C# | `csharp` | Compiled |
| Rust | `rust` | Compiled |
| Swift | `swift` | Compiled (macOS) |

### 1b. Create Exclusion Config (Interpreted Languages Only)

> **Skip this substep for compiled languages** - exclusion config is not supported when build tracing is required.

Scan for irrelevant files and create `codeql-config.yml`:

```bash
# Find common excludable directories
ls -d node_modules vendor third_party external deps 2>/dev/null || true

# Find test directories
fd -t d -E node_modules "test|tests|spec|__tests__|fixtures" .

# Find generated/minified files
fd -t f -E node_modules "\.min\.js$|\.bundle\.js$|\.generated\." . | head -20

# Estimate file counts
echo "Total source files:"
fd -t f -e py -e js -e ts -e go -e rb | wc -l
echo "In node_modules:"
fd -t f -e js -e ts node_modules 2>/dev/null | wc -l
```

**Create exclusion config:**

```yaml
# codeql-config.yml
paths-ignore:
  # Package managers
  - node_modules
  - vendor
  - venv
  - .venv
  # Third-party code
  - third_party
  - external
  - deps
  # Generated/minified
  - "**/*.min.js"
  - "**/*.bundle.js"
  - "**/generated/**"
  - "**/dist/**"
  # Tests (optional)
  # - "**/test/**"
  # - "**/tests/**"
```

```bash
log_step "Created codeql-config.yml"
log_result "Exclusions: $(grep -c '^  -' codeql-config.yml) patterns"
```

---

## Step 2: Build Database

### For Interpreted Languages (Python, JavaScript, Go, Ruby)

Single command, no build required:

```bash
log_step "Building database for interpreted language: <LANG>"
CMD="codeql database create $DB_NAME --language=<LANG> --source-root=. --codescanning-config=codeql-config.yml --overwrite"
log_cmd "$CMD"

$CMD 2>&1 | tee -a "$LOG_FILE"

if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS"
else
  log_result "FAILED"
fi
```

**Skip to Step 4 (Assess Quality) after success.**

---

### For Compiled Languages (Java, C/C++, C#, Rust, Swift)

Try build methods in sequence until one succeeds:

#### Method 1: Autobuild

```bash
log_step "METHOD 1: Autobuild"
CMD="codeql database create $DB_NAME --language=<LANG> --source-root=. --overwrite"
log_cmd "$CMD"

$CMD 2>&1 | tee -a "$LOG_FILE"

if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS"
else
  log_result "FAILED"
fi
```

#### Method 2: Custom Command

Detect build system and use explicit command:

| Build System | Detection | Command |
|--------------|-----------|---------|
| Make | `Makefile` | `make clean && make -j$(nproc)` |
| CMake | `CMakeLists.txt` | `cmake -B build && cmake --build build` |
| Gradle | `build.gradle` | `./gradlew clean build -x test` |
| Maven | `pom.xml` | `mvn clean compile -DskipTests` |
| Cargo | `Cargo.toml` | `cargo clean && cargo build` |
| .NET | `*.sln` | `dotnet clean && dotnet build` |
| Meson | `meson.build` | `meson setup build && ninja -C build` |
| Bazel | `BUILD`/`WORKSPACE` | `bazel build //...` |

**Find project-specific build scripts:**
```bash
# Look for custom build scripts
fd -t f -e sh -e bash -e py "build|compile|make|setup" .
ls -la build.sh compile.sh Makefile.custom configure 2>/dev/null || true

# Check README for build instructions
grep -i -A5 "build\|compile\|install" README* 2>/dev/null | head -20
```

Projects may have custom scripts (`build.sh`, `compile.sh`) or non-standard build steps documented in README. Use these instead of generic commands when found.

```bash
log_step "METHOD 2: Custom command"
log_step "Detected build system: <BUILD_SYSTEM>"
BUILD_CMD="<BUILD_CMD>"
CMD="codeql database create $DB_NAME --language=<LANG> --source-root=. --command='$BUILD_CMD' --overwrite"
log_cmd "$CMD"

$CMD 2>&1 | tee -a "$LOG_FILE"

if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS"
else
  log_result "FAILED"
fi
```

#### Method 3: Multi-step Build

For complex builds needing fine-grained control:

```bash
log_step "METHOD 3: Multi-step build"

# 1. Initialize
log_cmd "codeql database init $DB_NAME --language=<LANG> --source-root=. --overwrite"
codeql database init $DB_NAME --language=<LANG> --source-root=. --overwrite

# 2. Trace each build step
log_cmd "codeql database trace-command $DB_NAME -- <build step 1>"
codeql database trace-command $DB_NAME -- <build step 1>

log_cmd "codeql database trace-command $DB_NAME -- <build step 2>"
codeql database trace-command $DB_NAME -- <build step 2>
# ... more steps as needed

# 3. Finalize
log_cmd "codeql database finalize $DB_NAME"
codeql database finalize $DB_NAME

if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS"
else
  log_result "FAILED"
fi
```

#### Method 4: No-Build Fallback (Last Resort)

When all build methods fail, use `--build-mode=none` for partial analysis:

> **⚠️ WARNING:** This creates a database without build tracing. Analysis will be incomplete - only source-level patterns detected, no data flow through compiled code.

```bash
log_step "METHOD 4: No-build fallback (partial analysis)"
CMD="codeql database create $DB_NAME --language=<LANG> --source-root=. --build-mode=none --overwrite"
log_cmd "$CMD"

$CMD 2>&1 | tee -a "$LOG_FILE"

if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS (partial - no build tracing)"
else
  log_result "FAILED"
fi
```

---

## Step 3: Apply Fixes (if build failed)

Try these in order, then retry current build method. **Log each fix attempt:**

### 1. Clean existing state
```bash
log_step "Applying fix: clean existing state"
rm -rf "$DB_NAME"
log_result "Removed $DB_NAME"
```

### 2. Clean build cache
```bash
log_step "Applying fix: clean build cache"
CLEANED=""
make clean 2>/dev/null && CLEANED="$CLEANED make"
rm -rf build CMakeCache.txt CMakeFiles 2>/dev/null && CLEANED="$CLEANED cmake-artifacts"
./gradlew clean 2>/dev/null && CLEANED="$CLEANED gradle"
mvn clean 2>/dev/null && CLEANED="$CLEANED maven"
cargo clean 2>/dev/null && CLEANED="$CLEANED cargo"
log_result "Cleaned: $CLEANED"
```

### 3. Install missing dependencies

> **Note:** The commands below install the *target project's* dependencies so CodeQL can trace the build. Use whatever package manager the target project expects (`pip`, `npm`, `go mod`, etc.) — these are not the skill's own tooling preferences.

```bash
log_step "Applying fix: install dependencies"

# Python — use target project's package manager (pip/uv/poetry)
if [ -f requirements.txt ]; then
  log_cmd "pip install -r requirements.txt"
  pip install -r requirements.txt 2>&1 | tee -a "$LOG_FILE"
fi
if [ -f setup.py ] || [ -f pyproject.toml ]; then
  log_cmd "pip install -e ."
  pip install -e . 2>&1 | tee -a "$LOG_FILE"
fi

# Node - log installed packages
if [ -f package.json ]; then
  log_cmd "npm install"
  npm install 2>&1 | tee -a "$LOG_FILE"
fi

# Go
if [ -f go.mod ]; then
  log_cmd "go mod download"
  go mod download 2>&1 | tee -a "$LOG_FILE"
fi

# Java - log downloaded dependencies
if [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  log_cmd "./gradlew dependencies --refresh-dependencies"
  ./gradlew dependencies --refresh-dependencies 2>&1 | tee -a "$LOG_FILE"
fi
if [ -f pom.xml ]; then
  log_cmd "mvn dependency:resolve"
  mvn dependency:resolve 2>&1 | tee -a "$LOG_FILE"
fi

# Rust
if [ -f Cargo.toml ]; then
  log_cmd "cargo fetch"
  cargo fetch 2>&1 | tee -a "$LOG_FILE"
fi

log_result "Dependencies installed - see above for details"
```

### 4. Handle private registries

If dependencies require authentication, ask user:
```
AskUserQuestion: "Build requires private registry access. Options:"
  1. "I'll configure auth and retry"
  2. "Skip these dependencies"
  3. "Show me what's needed"
```

```bash
# Log authentication setup if performed
log_step "Private registry authentication configured"
log_result "Registry: <REGISTRY_URL>, Method: <AUTH_METHOD>"
```

**After fixes:** Retry current build method. If still fails, move to next method.

---

## Step 4: Assess Quality

Run all quality checks and compare against the project's expected source files.

### 4a. Collect Metrics

```bash
log_step "Assessing database quality"

# 1. Baseline lines of code and file list (most reliable metric)
codeql database print-baseline -- "$DB_NAME"
BASELINE_LOC=$(python3 -c "
import json
with open('$DB_NAME/baseline-info.json') as f:
    d = json.load(f)
for lang, info in d['languages'].items():
    print(f'{lang}: {info[\"linesOfCode\"]} LoC, {len(info[\"files\"])} files')
")
echo "$BASELINE_LOC"
log_result "Baseline: $BASELINE_LOC"

# 2. Source archive file count
SRC_FILE_COUNT=$(unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null | wc -l)
echo "Files in source archive: $SRC_FILE_COUNT"

# 3. Extraction errors from extractor diagnostics
EXTRACTOR_ERRORS=$(find "$DB_NAME/diagnostic/extractors" -name '*.jsonl' \
  -exec cat {} + 2>/dev/null | grep -c '^{' 2>/dev/null || true)
EXTRACTOR_ERRORS=${EXTRACTOR_ERRORS:-0}
echo "Extractor errors: $EXTRACTOR_ERRORS"

# 4. Export diagnostics summary (experimental but useful)
DIAG_TEXT=$(codeql database export-diagnostics --format=text -- "$DB_NAME" 2>/dev/null || true)
if [ -n "$DIAG_TEXT" ]; then
  echo "Diagnostics: $DIAG_TEXT"
fi

# 5. Check database is finalized
FINALIZED=$(grep '^finalised:' "$DB_NAME/codeql-database.yml" 2>/dev/null \
  | awk '{print $2}')
echo "Finalized: $FINALIZED"
```

### 4b. Compare Against Expected Source

Estimate the expected source file count from the working directory and compare:

```bash
# Count source files in the project (adjust extensions per language)
EXPECTED=$(fd -t f -e java -e kt --exclude 'codeql_*.db' \
  --exclude node_modules --exclude vendor --exclude .git . | wc -l)
echo "Expected source files: $EXPECTED"
echo "Extracted source files: $SRC_FILE_COUNT"

# Baseline LOC from database metadata
DB_LOC=$(grep '^baselineLinesOfCode:' "$DB_NAME/codeql-database.yml" \
  | awk '{print $2}')
echo "Baseline LoC: $DB_LOC"

# Error ratio
if [ "$SRC_FILE_COUNT" -gt 0 ]; then
  ERROR_RATIO=$(python3 -c "print(f'{$EXTRACTOR_ERRORS/$SRC_FILE_COUNT*100:.1f}%')")
else
  ERROR_RATIO="N/A (no files)"
fi
echo "Error ratio: $ERROR_RATIO ($EXTRACTOR_ERRORS errors / $SRC_FILE_COUNT files)"
```

### 4c. Log Assessment

```bash
log_step "Quality assessment results"
log_result "Baseline LoC: $DB_LOC"
log_result "Source archive files: $SRC_FILE_COUNT (expected: ~$EXPECTED)"
log_result "Extractor errors: $EXTRACTOR_ERRORS (ratio: $ERROR_RATIO)"
log_result "Finalized: $FINALIZED"

# Sample extracted files
unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null | head -20 >> "$LOG_FILE"
```

### Quality Criteria

| Metric | Source | Good | Poor |
|--------|--------|------|------|
| Baseline LoC | `print-baseline` / `baseline-info.json` | > 0, proportional to project size | 0 or far below expected |
| Source archive files | `src.zip` | Close to expected source file count | 0 or < 50% of expected |
| Extractor errors | `diagnostic/extractors/*.jsonl` | 0 or < 5% of files | > 5% of files |
| Finalized | `codeql-database.yml` | `true` | `false` (incomplete build) |
| Key directories | `src.zip` listing | Application code directories present | Missing `src/main`, `lib/`, `app/` etc. |
| "No source code seen" | build log | Absent | Present (cached build — compiled languages) |

**Interpreting baseline LoC:** A small number of extractor errors is normal and does not significantly impact analysis. However, if `baselineLinesOfCode` is 0 or the source archive contains no files, the database is empty — likely a cached build (compiled languages) or wrong `--source-root`.

---

## Step 5: Improve Quality (if poor)

Try these improvements, re-assess after each. **Log all improvements:**

### 1. Adjust source root
```bash
log_step "Quality improvement: adjust source root"
NEW_ROOT="./src"  # or detected subdirectory
# For interpreted: add --codescanning-config=codeql-config.yml
# For compiled: omit config flag
log_cmd "codeql database create $DB_NAME --language=<LANG> --source-root=$NEW_ROOT --overwrite"
codeql database create $DB_NAME --language=<LANG> --source-root=$NEW_ROOT --overwrite
log_result "Changed source-root to: $NEW_ROOT"
```

### 2. Fix "no source code seen" (cached build - compiled languages only)
```bash
log_step "Quality improvement: force rebuild (cached build detected)"
log_cmd "make clean && rebuild"
make clean && codeql database create $DB_NAME --language=<LANG> --overwrite
log_result "Forced clean rebuild"
```

### 3. Install type stubs / dependencies

> **Note:** These install into the *target project's* environment to improve CodeQL extraction quality.

```bash
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
log_cmd "pip install -e ."
pip install -e . 2>&1 | tee -a "$LOG_FILE"
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

---

## Exit Conditions

**Success:**
- Quality assessment shows GOOD
- User accepts current database state

**Failure (all methods exhausted):**
```
AskUserQuestion: "All build methods failed. Options:"
  1. "Accept current state" (if any database exists)
  2. "I'll fix the build manually and retry"
  3. "Abort"
```

---

## Final Report

**Finalize the log file:**
```bash
echo "=== Build Complete ===" >> "$LOG_FILE"
echo "Finished: $(date -Iseconds)" >> "$LOG_FILE"
echo "Final database: $DB_NAME" >> "$LOG_FILE"
echo "Successful method: <METHOD>" >> "$LOG_FILE"
echo "Final command: <EXACT_COMMAND>" >> "$LOG_FILE"
codeql resolve database -- "$DB_NAME" >> "$LOG_FILE" 2>&1
```

**Report to user:**
```
## Database Build Complete

**Database:** $DB_NAME
**Language:** <LANG>
**Build method:** autobuild | custom | multi-step
**Files extracted:** <COUNT>

### Quality:
- Errors: <N>
- Coverage: <good/partial/poor>

### Build Log:
See `$LOG_FILE` for complete details including:
- All attempted commands
- Fixes applied
- Quality assessments

**Final command used:**
<EXACT_COMMAND>

**Ready for analysis.**
```

---

## Performance: Parallel Extraction

Use `--threads` to parallelize database creation:

```bash
# Compiled language (no exclusion config)
codeql database create $DB_NAME --language=cpp --threads=0 --command='make -j$(nproc)'

# Interpreted language (with exclusion config)
codeql database create $DB_NAME --language=python --threads=0 \
  --codescanning-config=codeql-config.yml
```

**Note:** `--threads=0` auto-detects available cores. For shared machines, use explicit count.

---

## Quick Reference

| Language | Build System | Custom Command |
|----------|--------------|----------------|
| C/C++ | Make | `make clean && make -j$(nproc)` |
| C/C++ | CMake | `cmake -B build && cmake --build build` |
| Java | Gradle | `./gradlew clean build -x test` |
| Java | Maven | `mvn clean compile -DskipTests` |
| Rust | Cargo | `cargo clean && cargo build` |
| C# | .NET | `dotnet clean && dotnet build` |

See [language-details.md](../references/language-details.md) for more.
