# Working with compile_commands.json

This reference covers how to generate and use `compile_commands.json` for the zeroize-audit IR/ASM analysis pipeline. Read this before running Step 7 (IR comparison) or Step 8 (assembly analysis) in `task.md`.

---

## Structure

`compile_commands.json` is a JSON array where each entry describes the exact compiler invocation for one translation unit (TU):

```json
[
  {
    "directory": "/path/to/project/build",
    "arguments": [
      "clang", "-std=c11", "-I../include", "-DNDEBUG", "-Wall",
      "-c", "../src/crypto.c", "-o", "crypto.c.o"
    ],
    "file": "../src/crypto.c"
  },
  {
    "directory": "/path/to/project/build",
    "command": "clang++ -std=c++17 -I../include -DNDEBUG -c ../src/aead.cpp -o aead.cpp.o",
    "file": "../src/aead.cpp"
  }
]
```

**`arguments` vs `command`**: Some tools produce an `arguments` array (preferred); others produce a `command` string. `extract_compile_flags.py` handles both forms transparently.

**`directory`**: The working directory for the invocation. All relative paths in `arguments`/`command` and `file` are resolved against this field — **not** against the current working directory when running analysis. `extract_compile_flags.py` handles this automatically; manual invocations must account for it.

---

## Generating compile_commands.json

### CMake (C/C++)

```bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
# Output: build/compile_commands.json
```

**Constraints**: Works only with Makefile and Ninja generators. Does not work with Xcode or MSVC generators. Run from the project root and point `--compile-db` at `build/compile_commands.json`.

### Bear (any Make-based build system)

Bear intercepts compiler invocations at the OS level. Works with any `make`-based or custom build system:

```bash
# Install: apt install bear  OR  brew install bear
bear -- make clean all    # clean build recommended for accuracy
# Output: compile_commands.json in the current directory
```

Use `make clean all` rather than `make` alone to ensure all TUs are recompiled and captured. Incremental builds will only record the files that were actually recompiled.

### intercept-build (LLVM scan-build companion)

```bash
intercept-build make
# Output: compile_commands.json in the current directory
```

### Rust / Cargo

Cargo does not natively emit `compile_commands.json`. Two options:

```bash
# Option 1: Bear with cargo check (faster — avoids linking)
bear -- cargo check
bear -- cargo build   # if cargo check is insufficient

# Option 2: compiledb
pip install compiledb
compiledb cargo build
```

**Critical limitation for Rust**: Bear captures `rustc` invocations, not `clang` invocations. `emit_ir.sh` (which calls `clang`) **will not work** directly on Rust TUs. Use `cargo rustc` instead to emit IR and assembly directly:

```bash
# Preferred: use the emit scripts which handle CARGO_TARGET_DIR isolation:
{baseDir}/tools/emit_rust_ir.sh --manifest Cargo.toml --opt O0 --out /tmp/crate.O0.ll
{baseDir}/tools/emit_rust_ir.sh --manifest Cargo.toml --opt O2 --out /tmp/crate.O2.ll

# Manual alternative (output goes to an isolated temp dir, not target/debug/deps):
CARGO_TARGET_DIR=/tmp/zir cargo rustc -- --emit=llvm-ir -C opt-level=0
CARGO_TARGET_DIR=/tmp/zir cargo rustc -- --emit=llvm-ir -C opt-level=2

# Assembly for Rust (use instead of emit_asm.sh):
cargo rustc -- --emit=asm -C opt-level=2
# Output: target/release/deps/*.s
```

Pass the resulting `.ll` and `.s` files directly to `diff_ir.sh` and `analyze_asm.sh`.

---

## End-to-End Pipeline

The canonical pipeline for C/C++ analysis. Always use a hash of the source path as `<tu_hash>` (not the raw filename) to avoid collisions during parallel TU processing. Clean up temp files on completion or failure.

```bash
mkdir -p /tmp/zeroize-audit/

# Step 1: Extract build-relevant flags for the TU (as a bash array)
FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python {baseDir}/tools/extract_compile_flags.py \
    --compile-db /path/to/build/compile_commands.json \
    --src /path/to/src/crypto.c --format lines)

# Step 2: Emit IR at each level in opt_levels (always include O0 as baseline)
{baseDir}/tools/emit_ir.sh \
  --src /path/to/src/crypto.c \
  --out /tmp/zeroize-audit/<tu_hash>.O0.ll --opt O0 -- "${FLAGS[@]}"

{baseDir}/tools/emit_ir.sh \
  --src /path/to/src/crypto.c \
  --out /tmp/zeroize-audit/<tu_hash>.O1.ll --opt O1 -- "${FLAGS[@]}"

{baseDir}/tools/emit_ir.sh \
  --src /path/to/src/crypto.c \
  --out /tmp/zeroize-audit/<tu_hash>.O2.ll --opt O2 -- "${FLAGS[@]}"

# Step 3: Diff across all levels — O1 is the diagnostic level for simple DSE;
#         O2 catches more aggressive eliminations
{baseDir}/tools/diff_ir.sh \
  /tmp/zeroize-audit/<tu_hash>.O0.ll \
  /tmp/zeroize-audit/<tu_hash>.O1.ll \
  /tmp/zeroize-audit/<tu_hash>.O2.ll

# Step 4: Emit assembly at O2 for register-spill and stack-retention analysis
{baseDir}/tools/emit_asm.sh \
  --src /path/to/src/crypto.c \
  --out /tmp/zeroize-audit/<tu_hash>.O2.s --opt O2 -- "${FLAGS[@]}"

# Step 5: Analyze assembly output
{baseDir}/tools/analyze_asm.sh /tmp/zeroize-audit/<tu_hash>.O2.s

# Cleanup
rm -rf /tmp/zeroize-audit/<tu_hash>.*
```

Refer to the IR analysis reference (loaded separately from SKILL.md) for how to interpret IR diffs and identify wipe elimination patterns.

---

## Flags Stripped by extract_compile_flags.py

These flags are removed because they are irrelevant to or break single-file IR/ASM emission:

| Flag(s) | Reason stripped |
|---|---|
| `-o <file>` | Emission tools supply their own `-o` |
| `-c` | IR/ASM emission uses `-S -emit-llvm` / `-S` instead |
| `-MF`, `-MT`, `-MQ` (+ argument) | Dependency file generation — irrelevant for analysis |
| `-MD`, `-MMD`, `-MP`, `-MG` | Dependency generation side-effects |
| `-pipe` | OS pipe between compiler stages; not meaningful for direct calls |
| `-save-temps` | Saves intermediate files; produces clutter |
| `-gsplit-dwarf` | Splits debug info to `.dwo`; incompatible with single-file emission |
| `-fcrash-diagnostics-dir=...` | Crash report output; irrelevant |
| `-fmodule-file=...`, `-fmodules-cache-path=...` | Clang module paths; may confuse single-TU invocation |
| `--serialize-diagnostics` | Clang diagnostic binary output; not needed |
| `-fdebug-prefix-map=...` | Debug info path remapping; harmless to strip |
| `-fprofile-generate`, `-fprofile-use=...` | PGO instrumentation; distorts IR for analysis |
| `-fcoverage-mapping` | Coverage instrumentation; alters IR structure |

Flags that are **kept** (build-relevant):

| Pattern | Reason kept |
|---|---|
| `-I`, `-isystem`, `-iquote` | Include paths required to parse the TU |
| `-D`, `-U` | Preprocessor defines/undefines that affect code paths |
| `-std=<val>` | Language standard — affects syntax and semantics |
| `-f*` security/codegen flags | e.g., `-fstack-protector`, `-fPIC`, `-fno-omit-frame-pointer` |
| `-m<arch>` | Target architecture flags (e.g., `-m64`, `-march=x86-64`, `-mthumb`) |
| `-W*` | Warning flags — harmless to pass through |
| `-pthread` | Threading model; affects macro definitions |
| `--sysroot=`, `-isysroot` | System root for cross-compilation |
| `-target <triple>` | Cross-compilation target triple; must be preserved |

---

## Common Pitfalls

### 1. Relative paths and the `"directory"` field

`"file": "../src/crypto.c"` is relative to `"directory"`, not to the CWD when running analysis. Always resolve file paths using `"directory"`. `extract_compile_flags.py` does this automatically; be explicit if invoking `clang` manually.

### 2. Multiple entries for the same file

Some build systems emit duplicate entries (e.g., with and without a precompiled header). `extract_compile_flags.py` returns the **first** match. If that entry includes `-fpch-preprocess`, the PCH must exist in the build directory for compilation to succeed. Either regenerate the PCH or strip PCH-related flags manually.

### 3. Stale or incomplete compile DB (most common failure)

If `bear` or CMake was run on an incremental build, only recompiled TUs are recorded. TUs compiled in a previous run may be missing or have outdated flags. **Always generate the compile DB from a clean build** (`make clean all`, `cargo clean && cargo build`) to ensure all TUs are captured with current flags.

`extract_compile_flags.py` exits with code 2 if a source file is not found in the DB. Common causes:
- Header-only files (no TU entry — expected)
- Files added after the last `bear`/CMake run
- Symlinked paths that resolve differently than recorded

Regenerate the compile DB if entries are missing.

### 4. Generated source files

Entries may point to generated files in the build directory (e.g., `build/generated/config.c`) that don't exist in a clean checkout. Run the build system to generate them before running analysis. Preflight (Step 1 in `task.md`) will catch this if trial compilation is attempted.

### 5. Cross-compilation targets

If the compile DB was generated for a cross-compilation target (e.g., `-target aarch64-linux-gnu` or `-target thumbv7m-none-eabi`), emitted IR and assembly will be for that target, not x86-64. This affects analysis in two ways:

- **IR diffs**: Only compare IR files emitted for the same target. Do not mix targets across opt levels.
- **Assembly analysis**: `analyze_asm.sh` adapts register patterns by target:
  - x86-64: callee-saved registers are `rbx`, `r12`–`r15`; spills use `movq`/`movdqa` to `[rsp+N]`
  - AArch64: callee-saved registers are `x19`–`x28`; spills use `str`/`stp` to `[sp, #N]`
  - Thumb/ARM: callee-saved registers are `r4`–`r11`; spills use `str`/`stm` to `[sp, #N]`

Ensure `--target` is preserved in the stripped flags (it is, per the kept-flags table above).

### 6. `extract_compile_flags.py` exit codes

| Exit code | Meaning |
|---|---|
| 0 | Flags extracted successfully; output on stdout |
| 1 | Compile DB not found or not readable |
| 2 | Source file not found in compile DB |
| 3 | Compile DB is malformed JSON |

Check the exit code before passing flags to emission tools. An empty `FLAGS` array will silently produce incorrect IR.
