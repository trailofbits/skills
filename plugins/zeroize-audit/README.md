# zeroize-audit (Claude Skill)

Audits C/C++/Rust code for missing zeroization and compiler-removed wipes.
Pipeline: source scan → MCP/LSP semantic context → IR diff → assembly/MIR checks.

## Findings

- `MISSING_SOURCE_ZEROIZE`, `PARTIAL_WIPE`, `NOT_ON_ALL_PATHS`
- `OPTIMIZED_AWAY_ZEROIZE` (IR evidence required)
- `REGISTER_SPILL`, `STACK_RETENTION` (assembly evidence required for C/C++; LLVM IR evidence for Rust + optional assembly corroboration)
- `SECRET_COPY`, `INSECURE_HEAP_ALLOC`
- `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`, `LOOP_UNROLLED_INCOMPLETE`

## Prerequisites

### C/C++

- `compile_commands.json` is required (`compile_db` input field).
- Codebase must be buildable with commands from the compile DB.
- Required tools: `clang`, `uvx` (for Serena MCP server), `python3`.

```bash
which clang uvx python3
```

### Rust

- `Cargo.toml` path is required (`cargo_manifest` input field).
- Crate must be buildable (`cargo check` passes).
- Required tools: `cargo +nightly` toolchain, `uv`.

```bash
# Quick check
cargo +nightly --version
uv --version

# Full preflight validation (checks all tools, scripts, and optionally crate build)
tools/validate_rust_toolchain.sh --manifest path/to/Cargo.toml
tools/validate_rust_toolchain.sh --manifest path/to/Cargo.toml --json  # machine-readable
```

## Generate compile_commands.json (C/C++)

**CMake**
```bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

**Make/Bear**
```bash
bear -- make -j$(nproc)
```

## Usage

**C/C++ only:**
```json
{ "path": ".", "compile_db": "compile_commands.json" }
```

**Rust only:**
```json
{ "path": ".", "cargo_manifest": "Cargo.toml" }
```

**Mixed C/C++ + Rust:**
```json
{
  "path": ".",
  "compile_db": "compile_commands.json",
  "cargo_manifest": "Cargo.toml",
  "opt_levels": ["O0", "O1", "O2"],
  "mcp_mode": "prefer"
}
```

**Full C/C++ input:**
```json
{
  "path": ".",
  "compile_db": "compile_commands.json",
  "opt_levels": ["O0", "O1", "O2"],
  "languages": ["c", "cpp"],
  "config": "skills/zeroize-audit/configs/default.yaml",
  "max_tus": 50,
  "mcp_mode": "prefer",
  "mcp_required_for_advanced": true,
  "mcp_timeout_ms": 10000
}
```

## Agent Architecture

The analysis pipeline uses 10 agents across 8 phases, enabling parallel source analysis (C/C++ and Rust simultaneously), per-TU compiler analysis, mandatory PoC validation with verification, and protection against context pressure:

```
Phase 0: Orchestrator — Preflight + config + create workdir + enumerate TUs
Phase 1: Wave 1:  1-mcp-resolver              (skip if mcp_mode=off OR language_mode=rust)
         Wave 2a: 2-source-analyzer           (C/C++ only; skip if no compile_db)  ─┐ parallel
         Wave 2b: 2b-rust-source-analyzer     (Rust only; skip if no cargo_manifest) ─┘
Phase 2: Wave 3:  3-tu-compiler-analyzer x N  (C/C++ only; parallel, one per TU)
         Wave 3R: 3b-rust-compiler-analyzer   (Rust only; single agent, crate-level)
Phase 3: Wave 4:  4-report-assembler          (mode=interim → findings.json only)
Phase 4: Wave 5:  5-poc-generator             (mandatory; Rust findings marked poc_supported=false)
Phase 5: PoC Validation & Verification
         5a: 5b-poc-validator                 (compile and run all PoCs)
         5b: 5c-poc-verifier                  (verify each PoC proves its claimed finding)
         5c: Orchestrator presents verification failures to user
         5d: Orchestrator merges all results into poc_final_results.json
Phase 6: Wave 6:  4-report-assembler          (mode=final → merge PoC results, report)
Phase 7: Wave 7:  6-test-generator            (optional)
Phase 8: Orchestrator — Return final-report.md
```

| Agent | Phase | Purpose | Output Directory |
|---|---|---|---|
| `1-mcp-resolver` | 1, Wave 1 | Resolve symbols/types via Serena MCP (C/C++ only) | `mcp-evidence/` |
| `2-source-analyzer` | 1, Wave 2a | Sensitive objects, wipes, data-flow/heap (C/C++) | `source-analysis/` |
| `2b-rust-source-analyzer` | 1, Wave 2b | Rustdoc JSON trait analysis + dangerous API grep | `source-analysis/` |
| `3-tu-compiler-analyzer` | 2, Wave 3 | Per-TU IR diff, assembly, semantic IR, CFG (C/C++) | `compiler-analysis/{tu_hash}/` |
| `3b-rust-compiler-analyzer` | 2, Wave 3R | Crate-level MIR + LLVM IR analysis (Rust) | `rust-compiler-analysis/` |
| `4-report-assembler` | 3+6, Wave 4+6 | Collect findings, confidence gating; merge PoC results (invoked twice: interim + final) | `report/` |
| `5-poc-generator` | 4, Wave 5 | Generate proof-of-concept programs (C/C++ findings only) | `poc/` |
| `6-test-generator` | 7, Wave 7 | Generate runtime validation test harnesses (optional) | `tests/` |

Agents write persistent finding files to a shared working directory (`/tmp/zeroize-audit-{run_id}/`) with namespaced IDs to prevent collisions during parallel execution.

### ID Namespaces

| Entity | Pattern | Assigned By |
|---|---|---|
| Sensitive object (C/C++) | `SO-NNNN` | `2-source-analyzer` |
| Sensitive object (Rust) | `SO-5000+` | `2b-rust-source-analyzer` |
| Source finding (C/C++) | `F-SRC-NNNN` | `2-source-analyzer` |
| Source finding (Rust) | `F-RUST-SRC-NNNN` | `2b-rust-source-analyzer` |
| IR/assembly finding (C/C++) | `F-IR-{hash}-NNNN` | `3-tu-compiler-analyzer` |
| MIR finding (Rust) | `F-RUST-MIR-NNNN` | `3b-rust-compiler-analyzer` |
| LLVM IR finding (Rust) | `F-RUST-IR-NNNN` | `3b-rust-compiler-analyzer` |
| Assembly finding (Rust) | `F-RUST-ASM-NNNN` | `3b-rust-compiler-analyzer` |
| Final report finding | `ZA-NNNN` | `4-report-assembler` |

## Rust Analysis

Rust analysis runs in three layers — source, MIR, and LLVM IR — without requiring a language server (Rustdoc JSON replaces MCP for trait-aware semantics).

### Source Layer (`2b-rust-source-analyzer`)

**`tools/scripts/semantic_audit.py`** — Rustdoc JSON trait-aware analysis:

| Pattern | Category | Severity |
|---|---|---|
| `#[derive(Copy)]` on sensitive type | `SECRET_COPY` | critical |
| No `Zeroize`, `ZeroizeOnDrop`, or `Drop` impl | `MISSING_SOURCE_ZEROIZE` | high |
| Has `Zeroize` but no auto-trigger | `MISSING_SOURCE_ZEROIZE` | high |
| Partial `Drop` (not all secret fields zeroed) | `PARTIAL_WIPE` | high |
| `ZeroizeOnDrop` + `Vec`/`Box` heap fields | `PARTIAL_WIPE` | medium |
| `Clone` on zeroizing type | `SECRET_COPY` | medium |
| `From`/`Into` returning non-zeroizing type | `SECRET_COPY` | medium |
| `ptr::write_bytes` without `compiler_fence` | `OPTIMIZED_AWAY_ZEROIZE` | medium |
| `#[cfg(feature=...)]` wrapping Drop/Zeroize | `NOT_ON_ALL_PATHS` | medium |
| `#[derive(Debug)]` on sensitive type | `SECRET_COPY` | low |
| `#[derive(Serialize)]` on sensitive type | `SECRET_COPY` | low |
| No `zeroize` crate in Cargo.toml | `MISSING_SOURCE_ZEROIZE` | low |

**`tools/scripts/find_dangerous_apis.py`** — Token/grep scanner:

| API | Category | Severity |
|---|---|---|
| `mem::forget` | `MISSING_SOURCE_ZEROIZE` | critical |
| `ManuallyDrop::new` | `MISSING_SOURCE_ZEROIZE` | critical |
| `Box::leak` | `MISSING_SOURCE_ZEROIZE` | critical |
| `Box::into_raw` | `MISSING_SOURCE_ZEROIZE` | high |
| `ptr::write_bytes` | `OPTIMIZED_AWAY_ZEROIZE` | high |
| `mem::transmute` | `SECRET_COPY` | high |
| `slice::from_raw_parts` | `SECRET_COPY` | medium |
| async fn + secret local + `.await` | `NOT_ON_ALL_PATHS` | high |

### MIR Layer (`3b-rust-compiler-analyzer`)

**`tools/scripts/check_mir_patterns.py`** — Mid-level IR pattern analysis:

| Pattern | Category | Severity |
|---|---|---|
| Drop glue without `call zeroize::` | `MISSING_SOURCE_ZEROIZE` | high |
| `call extern "C"` with secret local | `SECRET_COPY` | high |
| `Yield` terminator with live sensitive local | `NOT_ON_ALL_PATHS` | high |
| `drop(_X)` without `StorageDead(_X)` on any path | `MISSING_SOURCE_ZEROIZE` | medium |
| `resume` terminator with live secret locals (unwind) | `MISSING_SOURCE_ZEROIZE` | medium |
| Secret moved into non-Zeroizing aggregate | `SECRET_COPY` | medium |

### LLVM IR Layer (`3b-rust-compiler-analyzer`)

**`tools/scripts/check_llvm_patterns.py`** — O0 vs O2 comparison (optional O1/O3 inputs supported):

| Pattern | Category | Severity |
|---|---|---|
| `store volatile` count drops O0 → O2 (global + per-symbol) | `OPTIMIZED_AWAY_ZEROIZE` | high |
| `@llvm.memset` without volatile flag | `OPTIMIZED_AWAY_ZEROIZE` | high |
| `alloca [N x i8]` present at O0, absent at O2 (SROA) | `OPTIMIZED_AWAY_ZEROIZE` | high |
| `alloca [N x i8]` with `@llvm.lifetime.end`, no `store volatile` | `STACK_RETENTION` | high |
| Secret SSA value loaded and passed to non-zeroize call | `REGISTER_SPILL` | medium |

### Assembly Layer (`3b-rust-compiler-analyzer`)

**`tools/scripts/check_rust_asm.py`** — x86-64 AT&T assembly analysis (runs when `enable_asm=true`). Corroborates LLVM IR findings; confidence upgrades to `confirmed` are applied by `3b-rust-compiler-analyzer` during cross-correlation when symbols match.

| Pattern | Category | Severity |
|---|---|---|
| `subq $N, %rsp` with no zero-store before `retq` | `STACK_RETENTION` | high |
| `movq/movdqa %reg, -N(%rsp)` (caller-saved register spill) | `REGISTER_SPILL` | medium |
| `drop_in_place::<T>` with no `call zeroize` | `MISSING_SOURCE_ZEROIZE` | medium |

Rust-specific handling: symbols are demangled via `rustfilt`; monomorphized instances of the same generic function are deduplicated (one finding emitted with instance count in evidence).
If non-x86-64 assembly is detected, the script writes empty findings and logs a warning (guardrail mode).

### Direct Tool Usage (Rust)

```bash
# Emit MIR
tools/emit_rust_mir.sh --manifest path/to/Cargo.toml --out /tmp/crate.mir

# Emit MIR for a specific crate in a workspace
tools/emit_rust_mir.sh --manifest path/to/Cargo.toml --crate my-crate --out /tmp/crate.mir

# Emit LLVM IR at O0 and O2
tools/emit_rust_ir.sh --manifest path/to/Cargo.toml --opt O0 --out /tmp/crate.O0.ll
tools/emit_rust_ir.sh --manifest path/to/Cargo.toml --opt O2 --out /tmp/crate.O2.ll

# Analyse source
uv run tools/scripts/semantic_audit.py \
  --rustdoc target/doc/mycrate.json --cargo-toml Cargo.toml --out findings.json
uv run tools/scripts/find_dangerous_apis.py --src src/ --out dangerous.json

# Analyse MIR
uv run tools/scripts/check_mir_patterns.py \
  --mir /tmp/crate.mir --secrets sensitive-objects.json --out mir-findings.json

# Analyse LLVM IR
uv run tools/scripts/check_llvm_patterns.py \
  --o0 /tmp/crate.O0.ll --o2 /tmp/crate.O2.ll --out ir-findings.json

# Emit assembly at O2 (supports --crate, --bin/--lib, --target, --intel-syntax)
tools/emit_rust_asm.sh --manifest path/to/Cargo.toml --opt O2 --out /tmp/crate.O2.s
tools/emit_rust_asm.sh --manifest path/to/Cargo.toml --opt O2 --out /tmp/crate.O2.s --lib --intel-syntax

# Analyse assembly (STACK_RETENTION, REGISTER_SPILL; corroborates IR findings)
uv run tools/scripts/check_rust_asm.py \
  --asm /tmp/crate.O2.s --secrets sensitive-objects.json --out asm-findings.json

# Compare MIR across opt levels (detects zeroize/drop-glue disappearance)
tools/emit_rust_mir.sh --manifest path/to/Cargo.toml --opt O0 --out /tmp/crate.O0.mir
tools/emit_rust_mir.sh --manifest path/to/Cargo.toml --opt O2 --out /tmp/crate.O2.mir
tools/diff_rust_mir.sh /tmp/crate.O0.mir /tmp/crate.O2.mir
```

## Tool flow (C/C++, direct)

```bash
FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python tools/extract_compile_flags.py \
    --compile-db build/compile_commands.json --src src/crypto.c --format lines)
tools/emit_ir.sh --src src/crypto.c --out /tmp/crypto.O0.ll --opt O0 -- "${FLAGS[@]}"
tools/emit_ir.sh --src src/crypto.c --out /tmp/crypto.O2.ll --opt O2 -- "${FLAGS[@]}"
tools/diff_ir.sh /tmp/crypto.O0.ll /tmp/crypto.O2.ll
tools/emit_asm.sh --src src/crypto.c --out /tmp/crypto.O2.s --opt O2 -- "${FLAGS[@]}"
tools/analyze_asm.sh --asm /tmp/crypto.O2.s --out /tmp/asm.json
```

## PoC generation (mandatory for C/C++)

Every C/C++ finding is validated against a bespoke proof-of-concept program crafted by the `5-poc-generator` agent. PoC generation, validation, and verification run automatically during the pipeline (Phases 4–6). Rust findings are excluded (`poc_supported: false`) and appear in `poc_manifest.json` with `"reason": "Rust finding — C PoC not applicable"`.

The PoC generator agent reads each finding and the corresponding source code, then crafts a tailored PoC program that exercises the specific vulnerable code path using real function signatures, variable names, and types. After compilation and execution, the PoC verifier agent checks that each PoC actually proves the vulnerability it claims to demonstrate.

Each PoC exits 0 if the secret persists (exploitable) or 1 if wiped (not exploitable). PoCs that fail verification are presented to the user for review.

Supported categories (C/C++ PoCs): `MISSING_SOURCE_ZEROIZE`, `OPTIMIZED_AWAY_ZEROIZE`, `STACK_RETENTION`, `REGISTER_SPILL`, `SECRET_COPY`, `MISSING_ON_ERROR_PATH`, `PARTIAL_WIPE`, `NOT_ON_ALL_PATHS`, `INSECURE_HEAP_ALLOC`, `LOOP_UNROLLED_INCOMPLETE`, `NOT_DOMINATING_EXITS`.

## Confidence gates

### C/C++

- `OPTIMIZED_AWAY_ZEROIZE`: require IR diff evidence.
- `STACK_RETENTION` and `REGISTER_SPILL`: require assembly evidence.
- `SECRET_COPY`, `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`: require MCP semantic evidence (or strong IR/CFG corroboration), otherwise downgrade to `needs_review`.
- Missing compile DB or non-buildable codebase is a hard failure.

### Rust

- `OPTIMIZED_AWAY_ZEROIZE`: require IR diff evidence (per-symbol volatile-store drop, non-volatile `@llvm.memset`, or SROA alloca disappearance with prior O0 wipe evidence). Never valid from MIR or source evidence alone.
- `STACK_RETENTION`: require `alloca [N x i8]` + `@llvm.lifetime.end` without `store volatile` in the same function. If `check_rust_asm.py` also flags the same symbol, confidence upgrades to `confirmed`.
- `REGISTER_SPILL`: require load of secret SSA value followed by pass to a non-zeroize call site. If `check_rust_asm.py` also flags the same symbol, confidence upgrades to `confirmed`.

## References

- `skills/zeroize-audit/references/compile-commands.md`
- `skills/zeroize-audit/references/ir-analysis.md`
- `skills/zeroize-audit/references/mcp-analysis.md`
