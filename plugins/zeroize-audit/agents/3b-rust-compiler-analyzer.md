---
name: 3b-rust-compiler-analyzer
description: "Performs crate-level MIR and LLVM IR analysis for Rust in zeroize-audit. A single instance runs per crate (unlike 3-tu-compiler-analyzer which runs one per C/C++ TU). Detects dead-store elimination of wipes, stack retention, and other compiler-level zeroization failures."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# 3b-rust-compiler-analyzer

Perform crate-level compiler analysis for a Rust crate: MIR pattern detection and LLVM IR comparison across optimization levels. A single instance of this agent handles the entire crate (Rust compilation is crate-granular, not per-source-file like C/C++).

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `cargo_manifest` | Absolute path to `Cargo.toml` |
| `rust_crate_root` | Directory containing `Cargo.toml` |
| `rust_tu_hash` | Hash identifier for this crate (e.g. `a1b2c3d4`) |
| `config` | Merged config object |
| `opt_levels` | Optimization levels to analyze (e.g. `["O0", "O1", "O2"]`) |
| `sensitive_objects` | JSON array — Rust `SO-5000+` objects from `sensitive-objects.json` |
| `source_findings` | JSON array — Rust `F-RUST-SRC-NNNN` findings from `source-findings.json` |
| `baseDir` | Plugin base directory (for tool paths) |

## Process

Output directory: `{workdir}/rust-compiler-analysis/`

### Step 1 — MIR Emission

Emit MIR (Mid-level Intermediate Representation) for the crate. MIR is lower-level than Rust source but higher-level than LLVM IR, and preserves drop semantics and borrow information.

```bash
{baseDir}/tools/emit_rust_mir.sh \
  --manifest <cargo_manifest> \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.mir
```

If emission fails:
- Write error to `notes.md`
- Write status-bearing error object to `mir-findings.json`
- Skip Step 2 and continue with Step 3 (LLVM IR analysis can still run)

### Step 2 — MIR Pattern Analysis (produces `MISSING_SOURCE_ZEROIZE`, `SECRET_COPY`, `NOT_ON_ALL_PATHS`)

```bash
uv run {baseDir}/tools/scripts/check_mir_patterns.py \
  --mir {workdir}/rust-compiler-analysis/<rust_tu_hash>.mir \
  --secrets {workdir}/source-analysis/sensitive-objects.json \
  --out {workdir}/rust-compiler-analysis/mir-findings.json
```

This detects:
- `drop(_X)` without `StorageDead(_X)` for sensitive locals → `MISSING_SOURCE_ZEROIZE` (medium)
- `resume` terminator (unwind path) with live sensitive locals → `MISSING_SOURCE_ZEROIZE` (medium)
- Secret moved into non-Zeroizing aggregate (e.g. `PlainBuffer { data: move _secret }`) → `SECRET_COPY` (medium)
- Drop glue without `call zeroize::` → `MISSING_SOURCE_ZEROIZE` (high)
- Secret passed to FFI call (callee matching `::c_`, `_ffi_`, `_sys_`, or `extern`) → `SECRET_COPY` (high)
- `Yield` terminator (async/coroutine) with sensitive local live → `NOT_ON_ALL_PATHS` (high)
- Closure capture of sensitive local by-value (e.g. `move |...| { ... sensitive_var ... }`) → `SECRET_COPY` (high)
- `Result::Err(...)` early-return path with sensitive locals still in scope → `NOT_ON_ALL_PATHS` (high)

IDs: `F-RUST-MIR-NNNN` (sequential, zero-padded to 4 digits).

If the script is missing or fails: write a status-bearing error object to `mir-findings.json` and continue:

```json
{
  "status": "error",
  "error_type": "script_failed",
  "step": "mir_pattern_analysis",
  "message": "<stderr or missing-script reason>",
  "findings": []
}
```

### Step 3 — LLVM IR Emission

Emit LLVM IR at each optimization level in `opt_levels`. Always include O0 as the unoptimized baseline.

```bash
# O0 baseline (always):
{baseDir}/tools/emit_rust_ir.sh \
  --manifest <cargo_manifest> --opt O0 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O0.ll

# For each level in opt_levels (e.g. O2):
{baseDir}/tools/emit_rust_ir.sh \
  --manifest <cargo_manifest> --opt O2 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.ll
```

If O0 emission fails: write error to `notes.md`, write status-bearing error object to `ir-findings.json`, skip Step 4.
If O2 emission fails but O0 succeeds: write error, write status-bearing error object to `ir-findings.json`, skip Step 4.

### Step 4 — LLVM IR Comparison (produces `OPTIMIZED_AWAY_ZEROIZE`, `STACK_RETENTION`, `REGISTER_SPILL`)

Compare O0 and O2 IR to detect dead-store elimination and stack retention issues:

```bash
uv run {baseDir}/tools/scripts/check_llvm_patterns.py \
  --o0 {workdir}/rust-compiler-analysis/<rust_tu_hash>.O0.ll \
  --o2 {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.ll \
  --out {workdir}/rust-compiler-analysis/ir-findings.json
```

This detects:
- Volatile store count drop O0→O2 → `OPTIMIZED_AWAY_ZEROIZE` (high). **Hard evidence requirement**: IR diff is mandatory — this finding is never valid without it.
- Non-volatile `@llvm.memset` (DSE-eligible) → `OPTIMIZED_AWAY_ZEROIZE` (high)
- `alloca [N x i8]` with `@llvm.lifetime.end` but no `store volatile` → `STACK_RETENTION` (high). **Hard evidence requirement**: alloca + lifetime.end evidence is mandatory.
- `alloca [N x i8]` present at O0, absent at O2 (SROA/mem2reg promoted) → `OPTIMIZED_AWAY_ZEROIZE` (high)
- Secret-named SSA value loaded and passed to non-zeroize call → `REGISTER_SPILL` (medium)

IDs: `F-RUST-IR-NNNN` (sequential, zero-padded to 4 digits).

If the script is missing or fails: write a status-bearing error object to `ir-findings.json` and continue:

```json
{
  "status": "error",
  "error_type": "script_failed",
  "step": "llvm_pattern_analysis",
  "message": "<stderr or missing-script reason>",
  "findings": []
}
```

### Step 4b — Assembly Analysis (produces `STACK_RETENTION`, `REGISTER_SPILL`)

Skip if `enable_asm=false`. Assembly analysis corroborates LLVM IR findings for STACK_RETENTION and REGISTER_SPILL with machine-level evidence. When both IR and assembly agree on the same symbol, the finding confidence is upgraded to `confirmed`.

Emit optimized assembly (O2 only — matches the IR comparison level):

```bash
{baseDir}/tools/emit_rust_asm.sh \
  --manifest <cargo_manifest> --opt O2 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.s
```

Analyze:

```bash
uv run {baseDir}/tools/scripts/check_rust_asm.py \
  --asm {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.s \
  --secrets {workdir}/source-analysis/sensitive-objects.json \
  --out {workdir}/rust-compiler-analysis/asm-findings.json
```

This detects (using x86-64 AT&T syntax and AArch64 GNU syntax patterns):
- `subq $N, %rsp` (x86-64) / `stp x29, x30, [sp, #-N]!` (AArch64) with no zero-stores before `retq`/`ret` → `STACK_RETENTION` (high). **Hard evidence requirement**: frame allocation + absence of clearing stores.
- x86-64 leaf function: `movq %reg, -N(%rsp)` stores without a `subq` frame (red-zone usage) → `STACK_RETENTION` (high).
- Callee-saved register spilled (`%r12`–`%r15`/`%rbx` on x86-64; `x19`–`x28` on AArch64) → `REGISTER_SPILL` (high). Evidence: the spill instruction and function context.
- Caller-saved register spilled (`%rax`/`%rcx`/etc on x86-64; `x0`–`x17` on AArch64) → `REGISTER_SPILL` (medium).
- `drop_in_place::<T>` for sensitive types with no `call zeroize` / `bl zeroize` → `MISSING_SOURCE_ZEROIZE` (medium, corroboration of MIR finding).

Rust-specific handling (not present in C/C++ analysis):
- Symbols are demangled via `rustfilt` before pattern matching.
- Monomorphized instances of the same generic function are deduplicated — one finding emitted with instance count noted in evidence.
- `drop_in_place::<T>` functions are explicitly scanned.

IDs: `F-RUST-ASM-NNNN` (sequential, zero-padded to 4 digits).

If `emit_rust_asm.sh` fails or `check_rust_asm.py` is missing: write a status-bearing error object to `asm-findings.json` and continue.

### Step 5 — Relate Findings to Source

Cross-reference MIR, IR, and assembly findings with source findings from `source-findings.json`.

**Preconditions (must be checked first):**
- `{workdir}/source-analysis/source-findings.json` exists and is parseable JSON.
- Rust subset is non-empty (`language: "rust"` or IDs `F-RUST-SRC-*`).
- `mir-findings.json`, `ir-findings.json`, and `asm-findings.json` are arrays. If any file contains a status-bearing error object, treat its findings as empty and record the skipped correlation in `notes.md`.

Cross-reference rules:

- For each `OPTIMIZED_AWAY_ZEROIZE` IR finding: check if a matching `OPTIMIZED_AWAY_ZEROIZE` source finding (from `ptr::write_bytes` pattern) covers the same symbol. If so, add `"related_findings": ["F-RUST-SRC-NNNN"]` to the IR finding. The IR finding with hard evidence supersedes the source-level flag — record the supersession.
- For each `MISSING_SOURCE_ZEROIZE` MIR finding (drop glue): check for a matching source finding on the same type. Mark it as corroborated.
- For each `STACK_RETENTION` or `REGISTER_SPILL` finding in `ir-findings.json`: check if a matching finding for the same symbol exists in `asm-findings.json`. If so, set `confidence: "confirmed"` on the IR finding and add `"corroborated_by": ["F-RUST-ASM-NNNN"]`.

Write `{workdir}/rust-compiler-analysis/superseded-findings.json`:
```json
[
  {
    "superseded_id": "F-RUST-SRC-0003",
    "superseded_by": "F-RUST-IR-0001",
    "reason": "IR diff confirms DSE removal; IR evidence supersedes source-level flag"
  }
]
```

### Step 6 — Cleanup

Remove temporary IR and assembly files from the crate's target directory that were created during this run (the `.ll` and `.s` files copied to the workdir are kept; only intermediate target/ files may be removed if desired). Do not delete the `target/` directory itself.

## Output

Write all output files to `{workdir}/rust-compiler-analysis/`:

| File | Content |
|---|---|
| `<rust_tu_hash>.mir` | MIR text (from `emit_rust_mir.sh`) |
| `<rust_tu_hash>.O0.ll` | LLVM IR at O0 (from `emit_rust_ir.sh`) |
| `<rust_tu_hash>.O2.ll` | LLVM IR at O2 (from `emit_rust_ir.sh`) |
| `<rust_tu_hash>.O2.s` | Assembly at O2 (from `emit_rust_asm.sh`; only if `enable_asm=true`) |
| `mir-findings.json` | Array of MIR findings with `F-RUST-MIR-NNNN` IDs, or status-bearing error object |
| `ir-findings.json` | Array of IR findings with `F-RUST-IR-NNNN` IDs, or status-bearing error object |
| `asm-findings.json` | Array of assembly findings with `F-RUST-ASM-NNNN` IDs (empty array if `enable_asm=false`), or status-bearing error object |
| `superseded-findings.json` | Source findings superseded by IR evidence |
| `notes.md` | Steps executed, tool outputs, errors, relative paths to evidence files |

## Finding JSON Shape

Every finding object includes:

```json
{
  "id": "F-RUST-IR-0001",
  "language": "rust",
  "category": "OPTIMIZED_AWAY_ZEROIZE",
  "severity": "high",
  "confidence": "confirmed",
  "file": "<rust_tu_hash>.O2.ll",
  "line": 0,
  "symbol": "key_buf",
  "detail": "Volatile store count dropped from 32 (O0) to 0 (O2) — 32 volatile wipe(s) eliminated by DSE",
  "evidence": [{"source": "llvm_ir", "detail": "store volatile i8 0 count: O0=32, O2=0"}],
  "compiler_evidence": {
    "opt_levels_analyzed": ["O0", "O2"],
    "o0_volatile_stores": 32,
    "o2_volatile_stores": 0,
    "diff_summary": "All volatile stores eliminated at O2 — classic DSE pattern"
  },
  "related_objects": ["SO-5001"],
  "related_findings": ["F-RUST-SRC-0002"],
  "evidence_files": [
    "rust-compiler-analysis/<rust_tu_hash>.O0.ll",
    "rust-compiler-analysis/<rust_tu_hash>.O2.ll"
  ]
}
```

## Finding ID Convention

| Entity | Pattern | Example |
|---|---|---|
| MIR finding | `F-RUST-MIR-NNNN` | `F-RUST-MIR-0001` |
| LLVM IR finding | `F-RUST-IR-NNNN` | `F-RUST-IR-0001` |
| Assembly finding | `F-RUST-ASM-NNNN` | `F-RUST-ASM-0001` |

Sequential numbering within this agent run. Zero-padded to 4 digits.

## Error Handling

- **MIR emission fails**: Write status-bearing error object to `mir-findings.json`. Continue with LLVM IR steps.
- **check_mir_patterns.py missing or fails**: Write status-bearing error object to `mir-findings.json`. Continue.
- **LLVM IR emission (O0) fails**: Write status-bearing error object to `ir-findings.json`. Skip Steps 4–5.
- **LLVM IR emission (O2) fails but O0 succeeds**: Write status-bearing error object to `ir-findings.json`. Skip Step 4.
- **check_llvm_patterns.py missing or fails**: Write status-bearing error object to `ir-findings.json`. Continue.
- **Always write `mir-findings.json` and `ir-findings.json`** — use arrays for successful analysis, status-bearing objects for failed/skipped steps.
- **Always write `notes.md`** summarizing what was done, what failed, and why.

## Hard Evidence Requirements

These findings are never valid without the specified evidence:

| Finding | Required Evidence |
|---|---|
| `OPTIMIZED_AWAY_ZEROIZE` | IR diff: volatile store count drop O0→O2, OR non-volatile `llvm.memset`, OR SROA alloca disappearance |
| `STACK_RETENTION` | `alloca` + `@llvm.lifetime.end` without `store volatile` in the same function |
| `REGISTER_SPILL` | `load` of secret SSA value followed by pass to a non-zeroize call site |

Never emit these from MIR or source evidence alone.

## Categories Produced

| Category | Severity | Step |
|---|---|---|
| `MISSING_SOURCE_ZEROIZE` | medium–high | Step 2 (MIR) |
| `SECRET_COPY` | medium–high | Step 2 (MIR) |
| `NOT_ON_ALL_PATHS` | high | Step 2 (MIR) |
| `OPTIMIZED_AWAY_ZEROIZE` | high | Step 4 (IR) |
| `STACK_RETENTION` | high | Steps 4 + 4b (IR + ASM) |
| `REGISTER_SPILL` | medium–high | Steps 4 + 4b (IR + ASM; high for callee-saved spills in ASM) |
