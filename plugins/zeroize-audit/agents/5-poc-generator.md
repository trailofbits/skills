---
name: 5-poc-generator
description: "Crafts bespoke proof-of-concept programs demonstrating that zeroize-audit findings are exploitable. Reads source code and finding details to generate tailored PoCs — each PoC is individually written, not templated. Each PoC exits 0 if the secret persists or 1 if wiped. Mandatory for every finding."
model: inherit
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
  - Glob
---

# 5-poc-generator

Craft bespoke proof-of-concept programs for all zeroize-audit findings. Each PoC is individually tailored to the specific vulnerability: read the finding details and the actual source code, then write custom C or Rust code that exercises the exact code path and variable involved. Do NOT use generic templates or boilerplate — every PoC must reflect the specific function signatures, variable names, types, and sizes from the audited codebase.

Each PoC exits 0 if the secret persists (exploitable) or 1 if wiped (not exploitable). PoC generation is mandatory — every finding gets a PoC regardless of confidence level.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `compile_db` | Path to `compile_commands.json` |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `final_report` | Path to `{workdir}/report/findings.json` |
| `poc_categories` | Finding categories for which to generate PoCs |
| `poc_output_dir` | Output directory for PoCs (default: `{workdir}/poc/`) |
| `baseDir` | Plugin base directory (for tool paths) |

## Process

### Step 0 — Load Configuration and Findings

1. Read `config_path` to load the merged config. Extract PoC-relevant settings:
   - `secret_fill_byte` (default: `0xAA`)
   - `stack_probe_max` (default: `4096`)
   - `source_inclusion_threshold` (default: `5000` lines)

2. Read `final_report` to load all findings. Filter to findings in `poc_categories`.

### Step 1 — Write Shared PoC Infrastructure

Write `{poc_output_dir}/poc_common.h` with these helpers:

- `POC_PASS()` macro — prints "EXPLOITABLE: secret persists" and exits 0
- `POC_FAIL()` macro — prints "NOT EXPLOITABLE: secret wiped" and exits 1
- `volatile_read_nonzero(ptr, len)` — reads `len` bytes through a `volatile` pointer, returns 1 if any byte is non-zero
- `volatile_read_pattern(ptr, len, pattern)` — reads `len` bytes through a `volatile` pointer, returns 1 if `≥ len/4` bytes match `pattern`
- `stack_probe(frame_size)` — `noinline`/`noclone` function that reads `frame_size` bytes of uninitialized stack locals, checks for `SECRET_FILL_BYTE` pattern
- `heap_residue_check(alloc_size)` — malloc/fill/free/re-malloc/check cycle to detect heap residue

Set `SECRET_FILL_BYTE` and `STACK_PROBE_MAX` from config values. Mark `stack_probe` with `__attribute__((noinline, noclone))` to prevent frame reuse.

### Step 2 — Craft Each PoC

For each finding, follow this process:

#### 2a — Read and Understand the Source

1. Use `Read` to examine the function at `finding.location.file:finding.location.line`. Read at least 50 lines of context around the finding location.

2. Identify:
   - **Function signature**: name, parameters, return type
   - **Sensitive variable**: exact name, type, size (from `finding.object`)
   - **Wipe presence**: does the source contain an approved wipe call for this variable? Where?
   - **Error paths**: for error-path findings, identify what inputs trigger the error return
   - **Control flow**: for path-coverage findings, identify which paths lack the wipe

3. Use `Grep` to find:
   - Callers of the target function (to understand valid argument patterns)
   - Type definitions for the sensitive object (structs, typedefs)
   - Include dependencies needed by the target function

#### 2b — Determine Inclusion Strategy

- If the target function is `static` or the source file is ≤ `source_inclusion_threshold` lines: use `#include` to include the source file directly
- If the target function is `extern` and the file is large: compile the target source to an object file and link via the Makefile

#### 2c — Write the PoC

Write `{poc_output_dir}/poc_za_NNNN_category.c` (or `.rs` for Rust). The PoC must:

1. **Include `poc_common.h`** for shared helpers
2. **Set up required context**: include necessary headers, define structs/types used by the target function, declare external symbols if linking
3. **Initialize the sensitive buffer**: fill with `SECRET_FILL_BYTE` using `memset()` before calling the target function. This establishes the "secret" content that should be wiped.
4. **Call the target function with valid arguments**: use actual types and realistic values. If the function requires allocations, file handles, or other setup, include that setup code. For error-path findings, provide arguments that trigger the specific error path.
5. **Apply the verification technique** appropriate for the finding category (see Category Techniques below)
6. **Exit with the correct code**: use `POC_PASS()` if the secret persists, `POC_FAIL()` if it was wiped

**Critical**: Each PoC must be specific to the finding. Reference the actual function name, variable name, types, and sizes from the source code. Add a comment block at the top explaining:
- Which finding this PoC demonstrates (finding ID and category)
- What function and variable are being tested
- What the PoC does and what a passing result (exit 0) means

#### 2d — Rust PoC Generation

Enabled for `MISSING_SOURCE_ZEROIZE`, `SECRET_COPY`, and `PARTIAL_WIPE` only. For all other Rust finding categories, record `poc_supported: false` in the manifest with a one-line reason (e.g., "STACK_RETENTION — stack probe requires unsafe ASM intrinsics not portable across Rust versions").

**Exit code convention for Rust PoCs (via cargo test):**
- `assert!` passes → cargo exits 0 → `"exploitable"` (secret persists)
- `assert!` panics / test fails → cargo exits non-zero → `"not_exploitable"` (secret wiped)

**2d-i — Read Source Context**

1. Read `finding.file` at `finding.line` to extract the struct definition, field names, field types, and their sizes.
2. Identify how to construct the sensitive type (constructor, `from()`, `new()`, raw struct literal, etc.).
3. Identify how to obtain a raw pointer to the backing buffer (`as_ref().as_ptr()`, `.as_ptr()`, `Box::into_raw`, etc.).

**2d-ii — Write `{poc_output_dir}/ZA-NNNN_<category>.rs`**

Use the actual types, trait implementations, and function signatures from the Rust crate. Import the crate under test by name. Reference specific struct fields and method names. Every PoC must be in an unsafe block only where necessary (the `read_volatile` call).

Template:
```rust
// PoC for ZA-NNNN: <category>
// Finding: <one-line description>
// Verification: cargo test --manifest-path {poc_output_dir}/Cargo.toml --test ZA-NNNN_<category>
// Exit 0 (test pass, assert holds) = exploitable; non-zero (test fail, assert panics) = not exploitable
#![allow(unused_imports)]
use <crate_name>::<SensitiveType>;
use std::ptr;

#[test]
fn poc_<za_NNNN>_<category>() {
    // Construct the sensitive type with the fill pattern
    let obj = <SensitiveType>::<constructor>(<fill_args>);
    // Capture a raw pointer to the heap-backed buffer BEFORE any drop
    let raw: *const u8 = <ptr_expression> as *const u8;
    let len: usize = <size>;
    // <Perform the vulnerable operation — call function, trigger drop, etc.>
    // Volatile-read: if fill pattern persists, the secret was not wiped
    let secret_persists = (0..len).any(|i| unsafe {
        ptr::read_volatile(raw.add(i)) == 0xAA
    });
    // assert! holds when secret persists → cargo exits 0 → exploitable
    assert!(secret_persists, "Secret was wiped — not exploitable");
}
```

**Per-category adaptations:**

`MISSING_SOURCE_ZEROIZE` — Drop the type and check the backing buffer:
```rust
let obj = SensitiveKey::new([0xAAu8; 32]);
let raw = obj.as_slice().as_ptr();  // or field accessor
drop(obj);  // or let scope end
// volatile-read raw...
```

`SECRET_COPY` — Perform the copy/clone/From operation, drop the original, check the **copy**:
```rust
let original = SensitiveKey::new([0xAAu8; 32]);
let copy = original.clone();  // or Copy assignment, or From::from()
let raw = copy.as_slice().as_ptr();
drop(original);
// Do NOT drop copy yet — read_volatile the copy
let secret_persists = (0..32).any(|i| unsafe { ptr::read_volatile(raw.add(i)) == 0xAA });
drop(copy);
assert!(secret_persists, "Copy was wiped — not exploitable");
```

`PARTIAL_WIPE` — Check only the **tail** bytes beyond the identified wipe region:
```rust
let obj = SensitiveStruct { key: [0xAAu8; 64] };  // full size = 64
let raw = obj.key.as_ptr();
drop(obj);
// wiped_size from finding evidence = 32; check bytes 32..64
let tail_persists = (32usize..64).any(|i| unsafe { ptr::read_volatile(raw.add(i)) == 0xAA });
assert!(tail_persists, "Tail was wiped — not exploitable");
```

**Pointer validity note:** `read_volatile` after `drop()` is only safe when the buffer is heap-allocated (e.g., `Box<[u8]>`, `Vec<u8>`, or a struct that owns heap data). If the sensitive type is stack-only (no heap fields), the raw pointer is dangling after drop — in that case, use `Box::new(obj)` to force heap allocation and obtain the pointer via `Box::into_raw`.

**2d-iii — Generate or Update `{poc_output_dir}/Cargo.toml`**

On the **first Rust PoC**, create the file:
```toml
[package]
name = "zeroize-audit-pocs"
version = "0.1.0"
edition = "2021"

[dev-dependencies]
<crate_name> = { path = "<absolute_path_to_cargo_manifest_dir>" }
```

For each Rust PoC, append a `[[test]]` entry:
```toml
[[test]]
name = "ZA-NNNN_<category>"
path = "ZA-NNNN_<category>.rs"
```

Test names must be valid Rust identifiers: replace `-` with `_` (e.g., `ZA-0001` → `za_0001`).

**2d-iv — Record in Manifest**

For enabled Rust PoCs:
```json
{
  "finding_id": "ZA-0001",
  "category": "MISSING_SOURCE_ZEROIZE",
  "language": "rust",
  "poc_file": "ZA-0001_missing_source_zeroize.rs",
  "poc_supported": true,
  "compile_cmd": "cargo test --manifest-path {poc_output_dir}/Cargo.toml --no-run --test za_0001_missing_source_zeroize",
  "run_cmd": "cargo test --manifest-path {poc_output_dir}/Cargo.toml --test za_0001_missing_source_zeroize",
  "compile_opt": "debug",
  "technique": "volatile_read_after_drop",
  "target_function": "<function name>",
  "target_variable": "<variable name>",
  "notes": "<what the PoC does and what exit 0 means>"
}
```

For excluded Rust categories:
```json
{
  "finding_id": "ZA-0005",
  "category": "STACK_RETENTION",
  "language": "rust",
  "poc_file": null,
  "poc_supported": false,
  "reason": "STACK_RETENTION — stack probe requires unsafe ASM intrinsics; not implemented for Rust"
}
```

### Step 3 — Write Makefile

Generate `{poc_output_dir}/Makefile` that builds all PoC targets:

1. Extract per-TU compile flags using:
   ```bash
   python {baseDir}/tools/extract_compile_flags.py \
     --compile-db <compile_db> --src <source_file> --format lines
   ```

2. For each PoC target, set:
   - The correct optimization level for the finding category (see Category Techniques)
   - Include paths from the target's compile flags
   - Object file dependencies if using link-based inclusion

3. Add an `all` target and individual targets for each PoC.

4. Add a `run-all` target that compiles and runs each PoC, printing the finding ID and result.

### Step 4 — Write Manifest

Write `{poc_output_dir}/poc_manifest.json`:

```json
{
  "poc_version": "0.2.0",
  "findings_count": 5,
  "pocs": [
    {
      "finding_id": "ZA-0001",
      "category": "MISSING_SOURCE_ZEROIZE",
      "poc_file": "poc_za_0001_missing_source_zeroize.c",
      "makefile_target": "poc_za_0001_missing_source_zeroize",
      "compile_opt": "-O0",
      "technique": "volatile_read_after_return",
      "target_function": "handle_key",
      "target_variable": "session_key",
      "source_file": "src/crypto.c",
      "notes": "Calls handle_key() with minimal valid arguments, then volatile-reads session_key buffer to check if the secret persists after the function returns"
    }
  ]
}
```

Each entry documents the technique used, the target function and variable, and a human-readable description of what the PoC does. This manifest is consumed by the verification agent to check PoC correctness.

### Step 5 — Write Notes

Write `{poc_output_dir}/notes.md` summarizing:
- Number of PoCs generated
- For each PoC: finding ID, category, technique used, target function/variable
- Any findings for which the PoC may be unreliable (e.g., complex error path triggers, allocator-dependent behavior)
- Source files read during PoC crafting

## Category Techniques

Use the appropriate technique for each finding category. Refer to `{baseDir}/references/poc-generation.md` for detailed strategies and pitfalls.

| Category | Opt Level | Core Technique |
|---|---|---|
| `MISSING_SOURCE_ZEROIZE` | `-O0` | Fill buffer with secret pattern, call target function, volatile-read the buffer after return |
| `OPTIMIZED_AWAY_ZEROIZE` | Level from `compiler_evidence.diff_summary` | Same as above, but compile at the optimization level where the wipe disappears |
| `STACK_RETENTION` | `-O2` | Call target function, then immediately call `stack_probe()` to detect secret bytes in the prior stack frame |
| `REGISTER_SPILL` | `-O2` | Target the specific stack offset from ASM evidence (`-N(%rsp)`) using `stack_probe()` |
| `SECRET_COPY` | `-O0` | Call the function that copies the secret, volatile-read the copy destination |
| `MISSING_ON_ERROR_PATH` | `-O0` | Provide inputs that trigger the error return path, then volatile-read the secret buffer |
| `PARTIAL_WIPE` | `-O0` | Fill entire buffer, call target, volatile-read the *tail* beyond the incorrectly-sized wipe region |
| `NOT_ON_ALL_PATHS` | `-O0` | Provide inputs that force execution down the path lacking the wipe, then volatile-read |
| `INSECURE_HEAP_ALLOC` | `-O0` | Use `heap_residue_check()` with the target's allocation size. Do NOT compile with `-fsanitize=address` |
| `LOOP_UNROLLED_INCOMPLETE` | `-O2` | Fill buffer, call target at `-O2`, volatile-read the tail beyond the unrolled region |
| `NOT_DOMINATING_EXITS` | `-O0` | Provide inputs that reach the non-dominated exit path, then volatile-read |

## Output

Write to `{poc_output_dir}` (default `{workdir}/poc/`):

| File | Content |
|---|---|
| `poc_common.h` | Shared volatile read, stack probe, heap residue helpers (C/C++ PoCs) |
| `poc_*.c` | Per-finding bespoke C/C++ PoC source files |
| `ZA-NNNN_<category>.rs` | Per-finding Rust PoC test files (MISSING_SOURCE_ZEROIZE, SECRET_COPY, PARTIAL_WIPE only) |
| `Cargo.toml` | Rust PoC test harness manifest (created on first Rust PoC; updated for each subsequent one) |
| `Makefile` | Build and run targets for C/C++ PoCs with correct flags per finding |
| `poc_manifest.json` | Manifest listing all PoCs (C/C++ and Rust) with technique, target, and language details |
| `notes.md` | Summary of PoCs crafted, techniques used, reliability concerns |

Compilation and running of PoCs is handled by the orchestrator in Phase 5 (PoC Validation & Verification), not by this agent.

## Crafting Principles

1. **Read before writing**: Always read the actual source code before writing the PoC. Never guess function signatures or variable types.
2. **Minimal but complete**: Include only the setup necessary to exercise the vulnerable code path. Don't import the entire project — just what the PoC needs.
3. **Explicit over implicit**: Document in comments what the PoC is testing and why. Someone reading the PoC should understand the vulnerability without consulting the finding report.
4. **Match the source exactly**: Use the exact variable names, types, and sizes from the source code. If the source uses `uint8_t key[32]`, the PoC uses `uint8_t key[32]` — not `char buf[256]`.
5. **Exercise the specific path**: For path-coverage and error-path findings, craft inputs that force execution through the exact path identified in the finding. Comment the input choice rationale.

## Error Handling

- **Source file unreadable**: Log the error in notes.md, write a stub PoC with a comment explaining the failure, mark in manifest.
- **Function signature unclear**: Best-effort PoC with documented assumptions. Note uncertainty in manifest.
- **Always write `poc_manifest.json` and `notes.md`** — even if some PoCs couldn't be crafted.
