# Mutation Testing Frameworks

Language-specific setup, execution, and output parsing for mutation testing.

## Contents

- Language detection
- Framework reference table
- Per-language setup and commands
- Parsing survived mutants
- Necessist (test statement removal)

---

## Installation Policy

**Every mutation testing framework listed below MUST be installed before
proceeding.** If a framework command is not found or fails to install:

1. Try the primary install method for the platform
2. Try the alternative install methods listed in the language section
3. If all methods fail, **report the error to the user** — do NOT fall
   back to "manual mutation analysis", "manual verification", or any
   other substitute that skips running the tool

Manual analysis is not a replacement for mutation testing. Mutation
testing tools systematically apply hundreds or thousands of mutations
that manual review cannot replicate. Skipping installation and doing
manual analysis produces false confidence with minimal actual coverage.

---

## Language Detection

Use file extensions to determine the target language, then select the
appropriate mutation framework:

| Extensions | Language | Framework |
|-----------|----------|-----------|
| `.py` | Python | pytest-gremlins or mutmut |
| `.js`, `.jsx`, `.ts`, `.tsx` | JavaScript/TypeScript | Stryker |
| `.rs` | Rust | cargo-mutants |
| `.go` | Go | gremlins or go-mutesting |
| `.java` | Java | PITest |
| `.c`, `.h`, `.cpp`, `.hpp`, `.cc` | C/C++ | Mull |
| `.cs` | C# | Stryker.NET |
| `.rb` | Ruby | mutant |
| `.php` | PHP | Infection |
| `.hs` | Haskell | MuCheck or Hedgehog |

---

## Python: pytest-gremlins (preferred) or mutmut

### pytest-gremlins

Faster alternative to mutmut. Uses mutation switching (no file I/O or
module reloads), coverage-guided test selection, and parallel execution.
Requires Python 3.11+.

**Install:**

```bash
uv add --dev pytest-gremlins
```

**Run:**

```bash
uv run pytest --gremlins
```

No configuration needed — it integrates directly with pytest.

**Parse survived mutants:** pytest-gremlins reports survived gremlins
in its test output. Each entry includes the file, line, mutation type,
and original/replacement values.

### mutmut

**Install:**

```bash
uv add --dev mutmut
```

**Configure** in `pyproject.toml`:

```toml
[tool.mutmut]
paths_to_mutate = "src/"
tests_dir = "tests/"
runner = "python -m pytest -x -q"
```

**Run:**

```bash
uv run mutmut run
uv run mutmut results
```

**Parse survived mutants:**

```bash
# List survived mutant IDs
uv run mutmut results | grep "Survived"

# Show specific mutant
uv run mutmut show <id>

# Export all results as JSON (mutmut 3.x+)
uv run mutmut junitxml > mutmut-results.xml
```

**Extract from results output:**
Each survived mutant line contains the file path, line number, and
mutation description. Parse with:

```bash
uv run mutmut results 2>&1 | grep "Survived" | \
  sed 's/.*Survived: //'
```

**macOS note:** If using rustworkx or other Rust extensions, set:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

---

## JavaScript/TypeScript: Stryker

**Install:**
```bash
pnpm add -D @stryker-mutator/core
pnpm dlx stryker init
```

**Configure** `stryker.config.json`:
```json
{
  "mutate": ["src/**/*.ts", "!src/**/*.test.ts"],
  "testRunner": "vitest",
  "reporters": ["json", "clear-text"],
  "jsonReporter": { "fileName": "stryker-report.json" }
}
```

**Run:**
```bash
pnpm dlx stryker run
```

**Parse survived mutants:**
```bash
# JSON report at reports/mutation/stryker-report.json
# Filter survived:
cat reports/mutation/stryker-report.json | \
  jq '.files | to_entries[] | .value.mutants[] | select(.status == "Survived")'
```

**Output fields:** `mutatorName`, `replacement`, `location.start.line`,
`location.start.column`, `fileName`.

---

## Rust: cargo-mutants

**Install:**
```bash
cargo install cargo-mutants
```

**Run:**
```bash
cargo mutants --json
```

**Parse survived mutants:**
```bash
# Results in mutants.out/outcomes.json
cat mutants.out/outcomes.json | \
  jq '.[] | select(.outcome == "survived")'
```

**Output fields:** `scenario.function`, `scenario.file`, `scenario.line`,
`scenario.replacement`, `outcome`.

**Filtering by module:**
```bash
cargo mutants --file src/parser.rs --json
```

---

## Go: gremlins (preferred) or go-mutesting

### gremlins

Actively maintained mutation testing tool for Go. Works best on
small-to-medium Go modules (microservices, libraries).

**Install:**

```bash
# macOS
brew tap go-gremlins/tap && brew install gremlins

# Any platform with Go
go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
```

**Run:**

```bash
gremlins unleash .
```

**Parse results:** gremlins reports survived mutants to stdout with
file path, line number, and mutation type.

### go-mutesting

**Install:**

```bash
go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest
```

**Run:**

```bash
go-mutesting ./...
```

**Parse results:** go-mutesting prints survived mutants to stdout.
Each line contains the file, line number, and mutation operator.

### Alternative: native fuzzing (Go 1.18+)

```bash
go test -fuzz=FuzzTarget -fuzztime=60s ./pkg/...
```

---

## Java: PITest

**Configure** in `pom.xml`:
```xml
<plugin>
  <groupId>org.pitest</groupId>
  <artifactId>pitest-maven</artifactId>
  <configuration>
    <targetClasses>com.example.*</targetClasses>
    <outputFormats>XML,CSV</outputFormats>
  </configuration>
</plugin>
```

**Run:**
```bash
mvn org.pitest:pitest-maven:mutationCoverage
```

**Parse survived mutants:**
```bash
# Results in target/pit-reports/mutations.xml
# Filter SURVIVED status
grep 'status="SURVIVED"' target/pit-reports/*/mutations.xml
```

**Output fields:** `mutatedClass`, `mutatedMethod`, `lineNumber`,
`mutator`, `status`.

---

## C/C++: Mull

Mull is an LLVM-based mutation testing tool for C and C++. It works as a
compiler plugin — it instruments the compiled test binary with mutations,
then selectively activates them during test execution.

**Mull requires a specific LLVM version.** Check the Mull releases page
for the LLVM version supported by the latest release. The project must
compile with the matching Clang version.

### Install

Mull is distributed as prebuilt binaries on GitHub Releases. Each
binary targets a specific LLVM version — **you must match the Mull
binary's LLVM version to the Clang version installed on the system.**

**Step 1: Determine your Clang/LLVM version:**

```bash
clang --version
# Look for the major version number (e.g., 19, 20)
```

If Clang is not installed, install it first. On macOS, use
`brew install llvm@<version>`. On Ubuntu, use
`sudo apt-get install clang-<version>`.

**Step 2: Download the matching Mull binary.**

Go to the [Mull releases page](https://github.com/mull-project/mull/releases/latest)
and download the asset matching your LLVM version, platform, and
architecture. Asset naming convention:

```text
Mull-<LLVM_MAJOR>-<MULL_VERSION>-LLVM-<LLVM_FULL>-<OS>-<ARCH>.<ext>
```

Examples (Mull 0.29.0):

| Platform | LLVM | Asset |
| -------- | ---- | ----- |
| macOS arm64 | 19 | `Mull-19-0.29.0-LLVM-19.1.7-macOS-aarch64-*.zip` |
| macOS arm64 | 20 | `Mull-20-0.29.0-LLVM-20.1.8-macOS-aarch64-*.zip` |
| Ubuntu 24.04 amd64 | 19 | `Mull-19-0.29.0-LLVM-19.1.1-ubuntu-amd64-24.04.deb` |
| Ubuntu 24.04 amd64 | 20 | `Mull-20-0.29.0-LLVM-20.1.2-ubuntu-amd64-24.04.deb` |
| RHEL 9 amd64 | 20 | `Mull-20-0.29.0-LLVM-20.1.8-rhel-amd64-9.6.rpm` |

**Step 3: Install.**

**macOS:**

```bash
# 1. Install the matching LLVM/Clang version via Homebrew
#    Check Mull releases for which LLVM versions are available
brew install llvm@18  # or llvm@19, llvm@20

# 2. Download the matching Mull binary
gh release download --repo mull-project/mull \
  --pattern 'Mull-18-*-macOS-aarch64-*.zip'  # match LLVM version
unzip Mull-18-*.zip

# 3. Install binaries to a known location
sudo mkdir -p /usr/local/bin /usr/local/lib
sudo cp usr/local/bin/mull-runner-* /usr/local/bin/
sudo cp usr/local/bin/mull-reporter-* /usr/local/bin/
sudo cp usr/local/lib/mull-ir-frontend-* /usr/local/lib/

# 4. Verify
mull-runner-18 --version
/opt/homebrew/opt/llvm@18/bin/clang --version
```

**Important macOS notes:**
- The Mull binary's LLVM version must **exactly match** the installed
  Clang. Using `brew install llvm@18` with `Mull-19-*` will not work.
- Use the Homebrew Clang, not Apple's system Clang (which is a
  different LLVM version and lacks plugin support).
- Set `ulimit -n 1024` before running `mull-runner` (see Environment
  Setup section below).

**Ubuntu/Debian:**

```bash
# Option A: Cloudsmith APT repository
curl -1sLf \
  'https://dl.cloudsmith.io/public/mull-project/mull-stable/setup.deb.sh' \
  | sudo -E bash
sudo apt-get update
sudo apt-get install mull-19  # match your LLVM version

# Option B: Direct .deb from GitHub
gh release download --repo mull-project/mull \
  --pattern 'Mull-19-*-ubuntu-amd64-24.04.deb'
sudo dpkg -i Mull-19-*.deb
```

**RHEL/Fedora:**

```bash
# Option A: Cloudsmith RPM repository
curl -1sLf \
  'https://dl.cloudsmith.io/public/mull-project/mull-stable/setup.rpm.sh' \
  | sudo -E bash
sudo dnf install mull-20  # match your LLVM version

# Option B: Direct .rpm from GitHub
gh release download --repo mull-project/mull \
  --pattern 'Mull-20-*-rhel-amd64-*.rpm'
sudo rpm -i Mull-20-*.rpm
```

**Verify installation:**

```bash
mull-runner --version
```

If `mull-runner` is not found after installation, check that the
install prefix is on `$PATH`. **DO NOT** fall back to "manual mutation
analysis" — fix the installation or report the error.

### Configure and Build

Mull requires the project to be compiled with Clang and the Mull
compiler plugin. The plugin injects mutations at the LLVM IR level.

**Key build requirements:**
- Use the **same Clang version** that matches your Mull release
- Pass `-fpass-plugin=<path-to-mull-ir-frontend>` to the compiler
- Use `-g -O0` (debug info required, no optimization)
- **Disable assembly** (`--disable-asm`) — Mull can only mutate
  LLVM IR, not hand-written assembly
- Disable hardening flags that interfere: `--disable-ssp --disable-pie`

**Find the plugin path:**

```bash
# The plugin is typically installed alongside mull-runner:
# Linux:  /usr/lib/mull-ir-frontend-<N>  (or mull-ir-frontend.so)
# macOS:  <install-prefix>/lib/mull-ir-frontend-<N>
# Use `find` or `locate` if unsure:
find /usr/local /opt/homebrew /tmp -name "mull-ir-frontend*" 2>/dev/null
```

**Simple projects:**

```bash
MULL_PLUGIN=$(find /usr/local /opt/homebrew -name "mull-ir-frontend*" 2>/dev/null | head -1)
clang -fpass-plugin=$MULL_PLUGIN -g -O0 \
  -o test_binary test_main.c src/*.c
```

**Autotools projects (configure/make):**

```bash
MULL_PLUGIN=$(find /usr/local /opt/homebrew -name "mull-ir-frontend*" 2>/dev/null | head -1)
LLVM_BIN=$(dirname $(which clang))  # or /opt/homebrew/opt/llvm@18/bin

CC=$LLVM_BIN/clang \
CFLAGS="-fpass-plugin=$MULL_PLUGIN -g -grecord-command-line -O0" \
./configure --disable-shared --enable-static --disable-asm \
  --disable-ssp --disable-pie
make clean && make -j$(nproc)
```

**CMake projects:**

```cmake
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(MULL_PLUGIN_PATH "" CACHE STRING "Path to Mull plugin")
if(MULL_PLUGIN_PATH)
  add_compile_options(-fpass-plugin=${MULL_PLUGIN_PATH} -g -O0)
endif()
```

```bash
MULL_PLUGIN=$(find /usr/local /opt/homebrew -name "mull-ir-frontend*" 2>/dev/null | head -1)
cmake -B build -DMULL_PLUGIN_PATH=$MULL_PLUGIN
cmake --build build
```

### Run

```bash
# Set FD limit (required on macOS, see Environment Setup)
ulimit -n 1024

# Run with GoogleTest binary
mull-runner --allow-surviving --no-output --timeout=5000 \
  --reporters=Elements --report-dir=mull-report ./build/tests

# Run with custom test command
mull-runner --test-program=ctest ./build/tests

# Generate report
mull-runner --report-dir=mull-report ./build/tests
```

**Recommended flags:**
- `--allow-surviving` — don't treat survived mutants as errors
- `--no-output` — suppress stdout/stderr from mutant runs
- `--timeout=5000` — 5 second timeout per mutant (adjust based on
  baseline test runtime; use 1000ms for tests completing in <100ms)
- `--reporters=Elements` — JSON output in Mutation Testing Elements
  format (machine-parseable for triage)
- `--report-dir=DIR` — write JSON reports to this directory
- `--report-name=NAME` — control output filename (useful when
  running multiple test binaries)
- `--workers=N` — parallelism for mutant execution (defaults to
  CPU count)

### Parse survived mutants

Mull outputs results to stdout and optionally to report files. Each
survived mutant includes the file path, line number, and mutation type.

```bash
# JSON report (if --report-dir used)
cat mull-report/mutation-testing-report.json | \
  jq '.files | to_entries[] | .value.mutants[] |
    select(.status == "Survived")'
```

### Environment Setup (Required)

**Before running `mull-runner`, always set a bounded file descriptor
limit.** On macOS (especially Tahoe / macOS 26+), the default
`ulimit -n` is `unlimited`, which causes Mull's subprocess library
(reproc) to fail with `EINVAL` when it tries to close inherited file
descriptors in the forked child process. The fix:

```bash
# REQUIRED before any mull-runner invocation
ulimit -n 1024
```

Add this to your Mull runner scripts or shell session. Without it,
you will see:

```
[error] Cannot run executable: Invalid argument
```

**Root cause:** reproc calls `getrlimit(RLIMIT_NOFILE)` to determine
the max FD to close. When the soft limit is `RLIM_INFINITY`, reproc
computes `max_fd = INT_MAX`, which exceeds its internal
`MAX_FD_LIMIT` (1048576) safety check, causing the child to exit
with `EMFILE`.

### Troubleshooting

| Problem | Solution |
| ------- | -------- |
| `mull-runner: command not found` | Install Mull using the instructions above |
| `Cannot run executable: Invalid argument` | Run `ulimit -n 1024` before `mull-runner` (see Environment Setup above) |
| LLVM version mismatch | Install the LLVM version matching your Mull release |
| Plugin load error | Recompile with matching Clang version |
| No mutants generated | Ensure `-g -O0` flags and Mull plugin are active |
| Tests fail without mutations | Fix test suite first — Mull needs a green baseline |
| Original test failed (timeout) | Increase `--timeout` or skip tests with long baseline runtimes |

---

## C#: Stryker.NET

**Install:**
```bash
dotnet tool install -g dotnet-stryker
```

**Run:**
```bash
dotnet stryker --reporter json
```

**Parse survived mutants:**
```bash
cat StrykerOutput/*/reports/mutation-report.json | \
  jq '.files | to_entries[] | .value.mutants[] | select(.status == "Survived")'
```

---

## Ruby: mutant

**Install:**
```bash
gem install mutant
```

**Run:**
```bash
bundle exec mutant run --include lib --require mylib 'MyLib*'
```

**Parse results:** mutant outputs surviving mutations to stdout with
file paths, line numbers, and mutation descriptions.

---

## PHP: Infection

**Install:**
```bash
composer require --dev infection/infection
```

**Run:**
```bash
vendor/bin/infection --show-mutations --min-msi=0
```

**Parse survived mutants:**
```bash
# JSON log at infection-log.json
cat infection-log.json | jq '.survived[]'
```

---

## Haskell: MuCheck or Hedgehog

MuCheck is the primary mutation testing tool for Haskell. For projects
without MuCheck support, property-based testing with Hedgehog or
QuickCheck serves as a mutation-resistant alternative.

### MuCheck

**Install:**
```bash
cabal install MuCheck
```

**Run:**
```bash
mucheck -t "cabal test" src/MyModule.hs
```

MuCheck applies standard mutation operators (negate guards, swap
operators, replace patterns) to the target module and runs the test
suite against each mutant.

**Parse survived mutants:** MuCheck prints results to stdout. Each
survived mutant includes the file path, line number, and mutation
description (e.g., "Negated guard on line 42").

**Limitations:** MuCheck requires the project to build with cabal and
has limited support for large multi-module projects. For Stack-based
projects, wrap the test command: `mucheck -t "stack test" src/Module.hs`.

### Alternative: property-based testing as mutation proxy

For projects where MuCheck is impractical, strong property-based tests
provide equivalent mutation resistance. Properties that assert invariants
over all inputs catch most mutations that MuCheck would surface.

**Hedgehog (preferred):**
```bash
cabal install hedgehog
```

Write properties in `test/` that cover arithmetic, branching, and
boundary behavior. A comprehensive property suite catches the same
classes of defects as mutation testing.

**QuickCheck:**
```bash
cabal install QuickCheck
```

QuickCheck properties work similarly. Use `forAll` with custom generators
to target the input domain of each function under test.

---

## Universal Mutant Record Format

Regardless of framework, normalize each survived mutant to this schema
before feeding into Phase 3 triage:

```json
{
  "file_path": "src/parser.py",
  "line": 42,
  "mutation_type": "arithmetic_operator",
  "original": "+",
  "replacement": "-",
  "function_name": "parse_header",
  "status": "survived"
}
```

Map the containing function name by matching `file_path:line` against
trailmark graph nodes using their `location.start_line` and
`location.end_line` ranges.

---

## Necessist: Test Statement Removal

Necessist complements mutation testing by removing statements and method
calls from **test code** and re-running the tests. If a test still passes
after a statement is removed, that statement may be unnecessary —
indicating weak assertions or missing coverage.

Mutation testing mutates production code to check if tests detect changes.
Necessist mutates test code to check if each test statement is actually
needed. Run both when the language supports it.

### Supported Frameworks

| Framework | Language | Auto-detected |
| --------- | -------- | ------------- |
| Anchor | Rust (Solana) | Yes |
| Foundry | Solidity | Yes |
| Go | Go | Yes |
| Hardhat (TypeScript) | TypeScript | Yes |
| Rust | Rust | Yes |
| Vitest | JavaScript/TypeScript | Yes |

Necessist auto-detects the framework from project files. Use `--framework`
to override when auto-detection fails.

### Install

```bash
cargo install necessist
```

### Run

```bash
# Auto-detect framework, run on all test files
necessist

# Explicit framework selection
necessist --framework foundry

# Target specific test files
necessist tests/test_parser.rs tests/test_validator.rs

# Set timeout per test (default 60s, 0 = no timeout)
necessist --timeout 120

# Resume a previous run (results stored in SQLite)
necessist --resume
```

### Parse Results

Necessist stores results in a SQLite database by default. Use `--dump`
to export:

```bash
necessist --dump
```

Each result line contains the test file, line number, the removed
statement, and whether the test passed or failed after removal. Filter
to **passed after removal** entries — these are the findings to triage.

### Configuration

Create `necessist.toml` in the project root (`necessist --default-config`
generates a template):

```toml
ignored_functions = ["println", "eprintln", "dbg"]
ignored_methods = ["clone", "to_string", "unwrap"]
ignored_macros = ["debug_assert", "trace"]
```

- `ignored_functions` — Skip removals of these function calls
- `ignored_methods` — Skip removals of these method calls
- `ignored_macros` — Skip removals of these macro invocations

For Foundry projects, consider ignoring common cheatcodes that are
setup-only (e.g., `vm.label`, `vm.deal` for labeling/funding).

### Normalized Necessist Record Format

Normalize each finding before feeding into Phase 3 triage:

```json
{
  "test_file_path": "tests/test_parser.rs",
  "test_line": 42,
  "removed_statement": "parser.validate(&input)",
  "test_function": "test_parse_header",
  "status": "passed_after_removal",
  "source": "necessist"
}
```

The `source` field distinguishes necessist findings from mutation testing
results during triage and reporting. Map the removed statement to a
production function using the algorithm in
[graph-analysis.md](../../genotoxic/references/graph-analysis.md).
