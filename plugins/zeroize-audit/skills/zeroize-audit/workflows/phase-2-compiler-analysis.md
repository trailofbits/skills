# Phase 2 — Compiler Analysis

## Preconditions

- Phase 1 complete: `tu-map.json` is non-empty
- `{workdir}/source-analysis/sensitive-objects.json` exists
- `{workdir}/source-analysis/source-findings.json` exists

## Instructions

### Wave 3 — TU Compiler Analyzers (C/C++ only, N parallel)

Skip if `language_mode=rust` or `tu-map.json` has no C/C++ entries.

For each C/C++ TU in `{workdir}/source-analysis/tu-map.json`:

1. Create output directory:
   ```bash
   mkdir -p {workdir}/compiler-analysis/<tu_hash>
   ```

2. Write per-TU agent input to `{workdir}/agent-inputs/tu-<tu_hash>.json`:
   ```json
   {
     "sensitive_objects": "<subset of sensitive-objects.json matching this TU>",
     "source_findings": "<subset of source-findings.json matching this TU>"
   }
   ```

3. Spawn agent `3-tu-compiler-analyzer` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `tu_source` | Source file path (from tu-map key) |
| `tu_hash` | TU hash (from tu-map value) |
| `compile_db` | `{{compile_db}}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `input_file` | `{workdir}/agent-inputs/tu-<tu_hash>.json` |
| `opt_levels` | `{{opt_levels}}` |
| `enable_asm` | `{{enable_asm}}` |
| `enable_semantic_ir` | `{{enable_semantic_ir}}` |
| `enable_cfg` | `{{enable_cfg}}` |
| `baseDir` | `{baseDir}` |

Launch TU agents in parallel using multiple `Task` calls in a single message. **Batching**: if the TU count exceeds 15, launch in batches of 10–15; wait for each batch before launching the next.

**After all TU agents complete**: Verify `{workdir}/compiler-analysis/<tu_hash>/ir-findings.json` exists for each TU. Log any failed TUs but continue.

### Wave 3R — Rust Compiler Analyzer (single agent)

Skip if any of the following are true:
- `language_mode=c`
- `tu-map.json` has no Rust entry (manifest key `.../Cargo.toml`)
- `sensitive-objects.json` is missing or empty
- `sensitive-objects.json` has no Rust objects (IDs `SO-5NNN` / `SO-5000+`)

Spawn agent `3b-rust-compiler-analyzer` via `Task` (after Wave 3 completes or is skipped):

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `cargo_manifest` | `{{cargo_manifest}}` |
| `rust_crate_root` | From `preflight.json` |
| `rust_tu_hash` | From `preflight.json` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `opt_levels` | `{{opt_levels}}` |
| `enable_asm` | `{{enable_asm}}` |
| `input_file` | `{workdir}/agent-inputs/rust-compiler.json` (write Rust-subset of sensitive-objects and source-findings before spawn) |
| `baseDir` | `{baseDir}` |

The `3b-rust-compiler-analyzer` agent must run these steps in order. On step failures, write status-bearing error objects to the affected output file(s) and continue.

**Step A — MIR analysis:**
```bash
{baseDir}/tools/emit_rust_mir.sh --manifest <cargo_manifest> --lib --opt O0 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.mir
uv run {baseDir}/tools/scripts/check_mir_patterns.py \
  --mir {workdir}/rust-compiler-analysis/<rust_tu_hash>.mir \
  --secrets {workdir}/source-analysis/sensitive-objects.json \
  --out {workdir}/rust-compiler-analysis/mir-findings.json
```

**Step B — LLVM IR analysis (O0 vs O2):**
```bash
{baseDir}/tools/emit_rust_ir.sh --manifest <cargo_manifest> --lib --opt O0 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O0.ll
{baseDir}/tools/emit_rust_ir.sh --manifest <cargo_manifest> --lib --opt O2 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.ll
uv run {baseDir}/tools/scripts/check_llvm_patterns.py \
  --o0 {workdir}/rust-compiler-analysis/<rust_tu_hash>.O0.ll \
  --o2 {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.ll \
  --out {workdir}/rust-compiler-analysis/ir-findings.json
```

**Step C — Assembly analysis** (skip if `enable_asm=false` or `emit_rust_asm.sh` missing):
```bash
{baseDir}/tools/emit_rust_asm.sh --manifest <cargo_manifest> --lib --opt O2 \
  --out {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.s
uv run {baseDir}/tools/scripts/check_rust_asm.py \
  --asm {workdir}/rust-compiler-analysis/<rust_tu_hash>.O2.s \
  --secrets {workdir}/source-analysis/sensitive-objects.json \
  --out {workdir}/rust-compiler-analysis/asm-findings.json
```

If assembly tools are missing, write `[]` to `asm-findings.json`.

IR finding IDs: `F-RUST-IR-NNNN`. MIR finding IDs: `F-RUST-MIR-NNNN`. Assembly finding IDs: `F-RUST-ASM-NNNN`.

Write `{workdir}/rust-compiler-analysis/notes.md` summarizing all steps, any failures, and key observations.

**After Wave 3R completes**: Verify `mir-findings.json`, `ir-findings.json`, and `asm-findings.json` exist under `{workdir}/rust-compiler-analysis/`. Log if missing, continue.

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 2,
  "phases": {
    "2": {"status": "complete", "tus_succeeded": "<N>", "tus_failed": "<N>"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| One TU agent (C/C++) fails | Continue with remaining TUs |
| All TU agents (C/C++) fail | Proceed — report assembler produces source-only report |
| Rust compiler analyzer (Wave 3R) fails | Log failure, continue — report assembler handles missing `rust-compiler-analysis/` |
| `emit_rust_asm.sh` missing | Write `[]` to `asm-findings.json`, continue — assembly findings skipped |
| MIR or IR emission fails | Write `[]` to that step's output, continue with remaining steps |

## Next Phase

Phase 3 — Interim Report
