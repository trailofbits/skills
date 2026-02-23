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
  2m. **macOS arm64 Toolchain** - Homebrew compiler + multi-step tracing (Apple Silicon workaround, see Step 2a)
  3. **Multi-step** - Fine-grained control with init → trace-command → finalize
  4. **No-build fallback** - `--build-mode=none` (partial analysis, last resort)

> **macOS Apple Silicon:** On arm64 Macs, system tools (`/usr/bin/make`, `/usr/bin/clang`, `/usr/bin/ar`) are built for `arm64e` (pointer-authenticated ABI), but CodeQL's `libtrace.dylib` only has `arm64`. macOS kills any `arm64e` process with a non-`arm64e` injected dylib (SIGKILL, exit 137). Step 2a detects this and routes to Method 2m which uses Homebrew tools (plain `arm64`) or Rosetta (`x86_64`).

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

#### Step 2a: macOS arm64e Detection (C/C++ only)

On macOS with Apple Silicon, CodeQL's build tracer (`preload_tracer`) injects `libtrace.dylib` into every spawned process via `DYLD_INSERT_LIBRARIES`. This dylib ships with `x86_64` + `arm64` slices, but Apple's system binaries (`/usr/bin/make`, `/usr/bin/clang`, `/usr/bin/ar`, `/bin/mkdir`, etc.) are built for `arm64e` (pointer-authenticated ABI). macOS kills any `arm64e` process that tries to load a non-`arm64e` injected dylib with **SIGKILL (signal 9, exit code 137)**.

**This affects C/C++ builds on macOS Apple Silicon when the build invokes any `arm64e` system tool under tracing.** Java, Swift, and other languages may also be affected if their build tools are `arm64e`.

**Detection:**

```bash
IS_MACOS_ARM64E=false
if [[ "$(uname -s)" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" ]]; then
  # Check if libtrace.dylib lacks arm64e
  LIBTRACE=$(find "$(dirname "$(command -v codeql)")" -name libtrace.dylib 2>/dev/null | head -1)
  if [ -n "$LIBTRACE" ]; then
    LIBTRACE_ARCHS=$(lipo -archs "$LIBTRACE" 2>/dev/null)
    if [[ "$LIBTRACE_ARCHS" != *"arm64e"* ]]; then
      # Check if system tools are arm64e
      MAKE_ARCHS=$(lipo -archs /usr/bin/make 2>/dev/null)
      if [[ "$MAKE_ARCHS" == *"arm64e"* ]]; then
        IS_MACOS_ARM64E=true
        log_step "DETECTED: macOS arm64e tracer incompatibility"
        log_result "libtrace.dylib archs: $LIBTRACE_ARCHS | /usr/bin/make archs: $MAKE_ARCHS"
      fi
    fi
  fi
fi
```

**If `IS_MACOS_ARM64E=true`:** Skip Method 1 (autobuild) and Method 2 (custom command) — they will fail with exit code 137. Go directly to **Method 2m (macOS arm64 toolchain)**.

**If `IS_MACOS_ARM64E=false`:** Proceed with Method 1, 2, 3 in normal order.

---

Try build methods in sequence until one succeeds:

#### Method 1: Autobuild

> **Skip if `IS_MACOS_ARM64E=true`** — autobuild spawns system tools that will be killed.

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

> **Skip if `IS_MACOS_ARM64E=true`** — custom command wraps the entire build in the tracer, which will inject `libtrace.dylib` into `arm64e` system tools called by make/cmake/etc.

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

#### Method 2m: macOS arm64 Toolchain (Apple Silicon workaround)

> **Use this method when `IS_MACOS_ARM64E=true`.** It replaces Methods 1 and 2 on affected systems.

The strategy is to use Homebrew-installed tools (which are plain `arm64`, not `arm64e`) so `libtrace.dylib` can be injected successfully. Try these sub-methods in order:

##### Sub-method 2m-a: Homebrew clang/gcc with multi-step tracing

Trace only the compiler invocations individually, avoiding system tools (`/usr/bin/ar`, `/bin/mkdir`) that would be killed. This requires a multi-step build: init → trace each compiler call → finalize.

```bash
log_step "METHOD 2m-a: macOS arm64 — Homebrew compiler with multi-step tracing"

# 1. Find Homebrew C/C++ compiler (arm64, not arm64e)
BREW_CC=""
# Prefer Homebrew clang
if [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then
  BREW_CC="/opt/homebrew/opt/llvm/bin/clang"
# Try Homebrew GCC (e.g. gcc-14, gcc-13)
elif command -v gcc-14 >/dev/null 2>&1; then
  BREW_CC="$(command -v gcc-14)"
elif command -v gcc-13 >/dev/null 2>&1; then
  BREW_CC="$(command -v gcc-13)"
fi

if [ -z "$BREW_CC" ]; then
  log_result "No Homebrew C/C++ compiler found — skipping 2m-a"
  # Fall through to 2m-b
else
  # Verify it's arm64 (not arm64e)
  BREW_CC_ARCH=$(lipo -archs "$BREW_CC" 2>/dev/null)
  if [[ "$BREW_CC_ARCH" == *"arm64e"* ]]; then
    log_result "Homebrew compiler is arm64e — skipping 2m-a"
  else
    log_step "Using Homebrew compiler: $BREW_CC (arch: $BREW_CC_ARCH)"

    # 2. Run the build normally (without tracing) to create build dirs and artifacts
    #    Use Homebrew make (gmake) if available, otherwise system make outside tracer
    if command -v gmake >/dev/null 2>&1; then
      MAKE_CMD="gmake"
    else
      MAKE_CMD="make"
    fi
    $MAKE_CMD clean 2>/dev/null || true
    $MAKE_CMD CC="$BREW_CC" 2>&1 | tee -a "$LOG_FILE"

    # 3. Extract compiler commands from the Makefile / build system
    #    Use make's dry-run mode to get the exact compiler invocations
    $MAKE_CMD clean 2>/dev/null || true
    COMPILE_CMDS=$($MAKE_CMD CC="$BREW_CC" --dry-run 2>/dev/null \
      | grep -E "^\s*$BREW_CC\b.*\s-c\s" \
      | sed 's/^[[:space:]]*//')

    if [ -z "$COMPILE_CMDS" ]; then
      log_result "Could not extract compile commands from dry-run — skipping 2m-a"
    else
      # 4. Init database
      codeql database init $DB_NAME --language=cpp --source-root=. --overwrite 2>&1 \
        | tee -a "$LOG_FILE"

      # 5. Ensure build directories exist (outside tracer — avoids arm64e mkdir)
      $MAKE_CMD clean 2>/dev/null || true
      #    Parse -o flags to find output dirs, or just create common dirs
      echo "$COMPILE_CMDS" | grep -oP '(?<=-o\s)\S+' | xargs -I{} dirname {} \
        | sort -u | xargs mkdir -p 2>/dev/null || true

      # 6. Trace each compiler invocation individually
      TRACE_OK=true
      while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        log_cmd "codeql database trace-command $DB_NAME -- $cmd"
        if ! codeql database trace-command $DB_NAME -- $cmd 2>&1 | tee -a "$LOG_FILE"; then
          log_result "FAILED on: $cmd"
          TRACE_OK=false
          break
        fi
      done <<< "$COMPILE_CMDS"

      if $TRACE_OK; then
        # 7. Finalize
        codeql database finalize $DB_NAME 2>&1 | tee -a "$LOG_FILE"
        if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
          log_result "SUCCESS (macOS arm64 multi-step)"
          # Done — skip to Step 4
        else
          log_result "FAILED (finalize failed)"
        fi
      fi
    fi
  fi
fi
```

##### Sub-method 2m-b: Rosetta x86_64 emulation

Force the entire CodeQL pipeline to run under Rosetta, which uses the `x86_64` slice of both `libtrace.dylib` and system tools — no `arm64e` mismatch.

```bash
log_step "METHOD 2m-b: macOS arm64 — Rosetta x86_64 emulation"

# Check if Rosetta is available
if ! arch -x86_64 /usr/bin/true 2>/dev/null; then
  log_result "Rosetta not available — skipping 2m-b"
else
  BUILD_CMD="<BUILD_CMD>"  # e.g. "make clean && make -j4"
  CMD="arch -x86_64 codeql database create $DB_NAME --language=<LANG> --source-root=. --command='$BUILD_CMD' --overwrite"
  log_cmd "$CMD"

  arch -x86_64 codeql database create $DB_NAME --language=<LANG> --source-root=. \
    --command="$BUILD_CMD" --overwrite 2>&1 | tee -a "$LOG_FILE"

  if codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
    log_result "SUCCESS (Rosetta x86_64)"
  else
    log_result "FAILED (Rosetta)"
  fi
fi
```

##### Sub-method 2m-c: System compiler (direct attempt)

As a verification step, try the standard autobuild with the system compiler. This will likely fail with exit code 137 on affected systems, but confirms the arm64e issue is the cause.

> **This sub-method is optional.** Skip it if arm64e incompatibility was already confirmed in Step 2a.

```bash
log_step "METHOD 2m-c: System compiler (expected to fail on arm64e)"
CMD="codeql database create $DB_NAME --language=<LANG> --source-root=. --overwrite"
log_cmd "$CMD"

$CMD 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=$?
if [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 134 ]; then
  log_result "FAILED: exit code $EXIT_CODE confirms arm64e/libtrace incompatibility"
elif codeql resolve database -- "$DB_NAME" >/dev/null 2>&1; then
  log_result "SUCCESS (unexpected — system compiler worked)"
else
  log_result "FAILED (exit code: $EXIT_CODE)"
fi
```

##### Sub-method 2m-d: Ask user

If all macOS workarounds fail, present options:

```
AskUserQuestion:
  header: "macOS Build"
  question: "Build tracing failed due to macOS arm64e incompatibility. How to proceed?"
  multiSelect: false
  options:
    - label: "Use build-mode=none (Recommended)"
      description: "Source-level analysis only. Misses some interprocedural data flow but catches most C/C++ vulnerabilities (format strings, buffer overflows, unsafe functions)."
    - label: "Install arm64 tools and retry"
      description: "Run: brew install llvm make — then retry with Homebrew toolchain"
    - label: "Install Rosetta and retry"
      description: "Run: softwareupdate --install-rosetta — then retry under x86_64 emulation"
    - label: "Abort"
      description: "Stop database creation"
```

**If "Use build-mode=none":** Proceed to Method 4.

**If "Install arm64 tools and retry":**
```bash
log_step "Installing Homebrew arm64 toolchain"
brew install llvm make 2>&1 | tee -a "$LOG_FILE"
# Retry Method 2m-a
```

**If "Install Rosetta and retry":**
```bash
log_step "Installing Rosetta"
softwareupdate --install-rosetta --agree-to-license 2>&1 | tee -a "$LOG_FILE"
# Retry Method 2m-b
```

---

#### Method 3: Multi-step Build

For complex builds needing fine-grained control:

> **On macOS with `IS_MACOS_ARM64E=true`:** Only trace compiler commands (arm64 Homebrew binaries). Do NOT trace system tools like `make`, `ar`, `mkdir` — they are arm64e and will be killed. Run non-compiler build steps outside the tracer.

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

Estimate the expected source file count from the working directory and compare.

> **Compiled languages (C/C++, Java, C#):** The source archive (`src.zip`) includes system headers and SDK files alongside project source files. For C/C++, this can inflate the archive count 10-20x (e.g., 111 archive files for 5 project source files). Compare against **project-relative files only** by filtering the archive listing.

```bash
# Count source files in the project (adjust extensions per language)
# C/C++: -e c -e cpp -e h -e hpp
# Java:  -e java -e kt
# Python: -e py
# JS/TS: -e js -e ts -e jsx -e tsx
EXPECTED=$(fd -t f -e c -e cpp -e h -e hpp -e java -e kt -e py -e js -e ts \
  --exclude 'codeql_*.db' --exclude node_modules --exclude vendor --exclude .git . \
  2>/dev/null | wc -l)
echo "Expected source files: $EXPECTED"

# Count PROJECT files in source archive (exclude system/SDK paths)
# For compiled languages, src.zip contains system headers under SDK paths
PROJECT_SRC_COUNT=$(unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null \
  | grep -v -E '^(Library/|usr/|System/|opt/|Applications/)' | wc -l)
echo "Project files in source archive: $PROJECT_SRC_COUNT"
echo "Total files in source archive: $SRC_FILE_COUNT (includes system headers for compiled langs)"

# Baseline LOC from database metadata (most reliable single metric)
DB_LOC=$(grep '^baselineLinesOfCode:' "$DB_NAME/codeql-database.yml" \
  | awk '{print $2}')
echo "Baseline LoC: $DB_LOC"

# Error ratio — use project file count for compiled langs, total for interpreted
if [ "$PROJECT_SRC_COUNT" -gt 0 ]; then
  ERROR_RATIO=$(python3 -c "print(f'{$EXTRACTOR_ERRORS/$PROJECT_SRC_COUNT*100:.1f}%')")
else
  ERROR_RATIO="N/A (no files)"
fi
echo "Error ratio: $ERROR_RATIO ($EXTRACTOR_ERRORS errors / $PROJECT_SRC_COUNT project files)"
```

### 4c. Log Assessment

```bash
log_step "Quality assessment results"
log_result "Baseline LoC: $DB_LOC"
log_result "Project source files: $PROJECT_SRC_COUNT (expected: ~$EXPECTED)"
log_result "Total archive files: $SRC_FILE_COUNT (includes system headers for compiled langs)"
log_result "Extractor errors: $EXTRACTOR_ERRORS (ratio: $ERROR_RATIO)"
log_result "Finalized: $FINALIZED"

# Sample extracted project files (exclude system paths)
unzip -Z1 "$DB_NAME/src.zip" 2>/dev/null \
  | grep -v -E '^(Library/|usr/|System/|opt/|Applications/)' \
  | head -20 >> "$LOG_FILE"
```

### Quality Criteria

| Metric | Source | Good | Poor |
|--------|--------|------|------|
| Baseline LoC | `print-baseline` / `baseline-info.json` | > 0, proportional to project size | 0 or far below expected |
| Project source files | `src.zip` (filtered) | Close to expected source file count | 0 or < 50% of expected |
| Extractor errors | `diagnostic/extractors/*.jsonl` | 0 or < 5% of project files | > 5% of project files |
| Finalized | `codeql-database.yml` | `true` | `false` (incomplete build) |
| Key directories | `src.zip` listing | Application code directories present | Missing `src/main`, `lib/`, `app/` etc. |
| "No source code seen" | build log | Absent | Present (cached build — compiled languages) |

**Interpreting archive file counts for compiled languages:** C/C++ databases include system headers (e.g., `<stdio.h>`, SDK headers) in `src.zip`. A project with 5 source files may have 100+ files in the archive. Always filter to project-relative paths when comparing against expected counts. Use `baselineLinesOfCode` as the primary quality indicator.

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

### macOS Apple Silicon (arm64e workaround)

| Priority | Method | Command |
|----------|--------|---------|
| 1st | Homebrew clang + multi-step | `codeql database init` → `codeql database trace-command -- /opt/homebrew/opt/llvm/bin/clang -c file.c` (per file) → `codeql database finalize` |
| 2nd | Rosetta x86_64 | `arch -x86_64 codeql database create --command='make'` |
| 3rd | `build-mode=none` | `codeql database create --build-mode=none` (source-level only) |

**Why:** CodeQL's `libtrace.dylib` has `x86_64`+`arm64` slices but Apple system tools are `arm64e`. macOS kills `arm64e` processes that load non-`arm64e` injected dylibs.

**Key constraint:** Only trace `arm64` binaries (Homebrew tools). Never trace `arm64e` binaries (`/usr/bin/*`, `/bin/*`) — they will be killed with signal 9.

See [language-details.md](../references/language-details.md) for more.
