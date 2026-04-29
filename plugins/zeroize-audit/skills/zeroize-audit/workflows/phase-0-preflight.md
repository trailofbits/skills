# Phase 0 — Preflight, Configuration, and Work Directory

## Preconditions

None — this is the first phase.

## Instructions

Spawn agent `0-preflight` via `Task` with:

| Parameter | Value |
|---|---|
| `path` | `{{path}}` |
| `compile_db` | `{{compile_db}}` |
| `cargo_manifest` | `{{cargo_manifest}}` |
| `config` | `{{config}}` |
| `languages` | `{{languages}}` |
| `max_tus` | `{{max_tus}}` |
| `mcp_mode` | `{{mcp_mode}}` |
| `mcp_timeout_ms` | `{{mcp_timeout_ms}}` |
| `mcp_required_for_advanced` | `{{mcp_required_for_advanced}}` |
| `enable_asm` | `{{enable_asm}}` |
| `enable_semantic_ir` | `{{enable_semantic_ir}}` |
| `enable_cfg` | `{{enable_cfg}}` |
| `enable_runtime_tests` | `{{enable_runtime_tests}}` |
| `opt_levels` | `{{opt_levels}}` |
| `poc_categories` | `{{poc_categories}}` |
| `poc_output_dir` | `{{poc_output_dir}}` |
| `baseDir` | `{baseDir}` |

The agent creates the work directory, runs all preflight checks, merges configuration, enumerates TUs, and writes `orchestrator-state.json`.

### What the `0-preflight` agent must do

**Step 1 — Determine language mode** from inputs:
- `compile_db` set and `cargo_manifest` not set → `language_mode=c`
- `cargo_manifest` set and `compile_db` not set → `language_mode=rust`
- Both set → `language_mode=mixed`
- Neither set → **stop the run**: at least one of `compile_db` or `cargo_manifest` is required.

**Step 2 — C/C++ preflight** (skip if `language_mode=rust`):

1. Verify `compile_db` file exists at the given path.
2. Verify at least one entry in the compile DB resolves to an existing source file and working directory.
3. Attempt a trial compilation of one representative TU using its captured flags to confirm the codebase is buildable.
4. Verify `{baseDir}/tools/extract_compile_flags.py` exists and is executable.
5. Verify `{baseDir}/tools/emit_ir.sh` exists and is executable.
6. If `enable_asm=true`: verify `{baseDir}/tools/emit_asm.sh` exists; if missing, set `enable_asm=false` and emit a warning.
7. If `mcp_mode != off`: run `{baseDir}/tools/mcp/check_mcp.sh` to probe MCP availability.
   - If `mcp_mode=require` and MCP is unreachable: **stop the run** and report the MCP failure.
   - If `mcp_mode=prefer` and MCP is unreachable: set `mcp_available=false`, continue, and apply confidence downgrades in the report assembly phase.

**Step 3 — Common preflight** (always):

8. Verify `{baseDir}/tools/generate_poc.py` exists and is executable. If missing: **stop the run** — PoC generation is mandatory.

**Step 4 — Rust preflight** (skip if `language_mode=c`):

9. Verify `cargo_manifest` file exists (must be a `Cargo.toml` path).
10. Run `cargo check --manifest-path <cargo_manifest>` to confirm the crate is buildable. If it fails: **stop the run**.
11. Verify `cargo +nightly --version` succeeds. If not: **stop the run** — nightly toolchain is required for MIR and LLVM IR emission.
    - Note: use `~/.cargo/bin/cargo +nightly` (rustup proxy) rather than a system cargo that may not support the `+toolchain` syntax.
12. Verify `uv --version` succeeds. If not: **stop the run** — `uv` is required to run Python analysis scripts.
13. Verify `{baseDir}/tools/emit_rust_mir.sh` exists and is executable. If missing: **stop the run** — MIR analysis is required.
14. Verify `{baseDir}/tools/emit_rust_ir.sh` exists and is executable. If missing: **stop the run** — LLVM IR analysis is required.
15. For each tool below: if missing or not executable, warn and mark that capability as skipped (do not fail the run):
    - `{baseDir}/tools/emit_rust_asm.sh` — if missing, set `enable_asm=false` for Rust; warn `STACK_RETENTION`/`REGISTER_SPILL` findings will be skipped.
    - `{baseDir}/tools/diff_rust_mir.sh` — if missing, warn that MIR-level optimization comparison will be skipped.
16. For each Python script below: if missing, warn and mark that sub-step as skipped (do not fail the run):
    - `{baseDir}/tools/scripts/semantic_audit.py`
    - `{baseDir}/tools/scripts/find_dangerous_apis.py`
    - `{baseDir}/tools/scripts/check_mir_patterns.py`
    - `{baseDir}/tools/scripts/check_llvm_patterns.py`
    - `{baseDir}/tools/scripts/check_rust_asm.py` — if missing, assembly analysis findings (`STACK_RETENTION`, `REGISTER_SPILL`) will be skipped even if `enable_asm=true`.

**Step 5 — TU / crate enumeration**:

- **C/C++** (skip if `language_mode=rust`): Parse `compile_db` and enumerate all translation units. Apply `max_tus` limit if set. Filter by `languages`. Compute `tu_hash = sha1(source_path)[:8]` for each TU. Run a lightweight grep across TU sources for sensitive name patterns (from merged config) to produce `sensitive_candidates`.
- **Rust** (skip if `language_mode=c`): Compute `rust_tu_hash = sha1(abspath(cargo_manifest))[:8]`. Set `rust_crate_root = dirname(cargo_manifest)`.

**Step 6 — Create work directory**:

```bash
RUN_ID=$(date +%Y%m%d%H%M%S)
WORKDIR="/tmp/zeroize-audit-${RUN_ID}"
mkdir -p "${WORKDIR}"/{mcp-evidence,source-analysis,compiler-analysis,rust-compiler-analysis,report,poc,tests,agent-inputs}
```

**Step 7 — Write `{workdir}/preflight.json`**:

```json
{
  "run_id": "<RUN_ID>",
  "timestamp": "<ISO-8601>",
  "repo": "<path>",
  "language_mode": "<c|rust|mixed>",
  "compile_db": "<compile_db or null>",
  "cargo_manifest": "<cargo_manifest or null>",
  "rust_crate_root": "<dirname(cargo_manifest) or null>",
  "rust_tu_hash": "<hash or null>",
  "opt_levels": ["O0", "O1", "O2"],
  "mcp_mode": "<mcp_mode>",
  "mcp_available": true,
  "enable_asm": true,
  "enable_semantic_ir": false,
  "enable_cfg": false,
  "enable_runtime_tests": false,
  "tu_count": 0,
  "tu_list": [{"file": "/path/to/file.c", "tu_hash": "a1b2c3d4"}],
  "sensitive_candidates": [],
  "tools_verified": ["uv", "cargo+nightly"],
  "notes": ""
}
```

**Step 8 — Write `{workdir}/orchestrator-state.json`** with the full state structure.

Report each preflight failure with the specific check that failed and the remediation step.

**After completion**: The agent's response includes the `workdir` path. Read `{workdir}/orchestrator-state.json` to initialize:

- `workdir` — use for all subsequent phases
- `routing.mcp_available` — MCP probe result
- `routing.tu_count` — number of TUs to process
- `key_file_paths.config` — path to merged config file

## State Update

The `0-preflight` agent writes the initial `orchestrator-state.json`. No additional update needed by the orchestrator.

## Error Handling

| Failure | Behavior |
|---|---|
| Agent fails or times out | Stop the run, report failure |
| Neither `compile_db` nor `cargo_manifest` provided | Stop the run |
| Preflight validation fails | Stop the run (agent reports specific check and remediation) |
| Config load fails | Stop the run |
| Preflight tool check fails | Stop the run |
| MCP unreachable + `mcp_mode=require` | Stop the run |
| MCP unreachable + `mcp_mode=prefer` | Continue — `routing.mcp_available` will be `false` |
| `cargo check` fails (Rust preflight) | Stop the run — crate must be buildable |
| `cargo +nightly` not available (Rust preflight) | Stop the run — nightly required for MIR/IR emission |
| `uv` not available (Rust preflight) | Stop the run — required for Python analysis scripts |
| `emit_rust_asm.sh` missing (Rust preflight) | Warn, set `enable_asm=false` for Rust, continue |
| Python script missing (Rust preflight) | Warn and skip that sub-step, continue |

## Next Phase

Phase 1 — Source Analysis
