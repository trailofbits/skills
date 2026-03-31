---
name: 0-preflight
description: "Performs preflight validation, config merging, TU enumeration, and work directory setup for zeroize-audit. Produces merged-config.yaml, preflight.json, and orchestrator-state.json."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# 0-preflight

Validate all prerequisites, merge configuration, enumerate translation units, and create the run working directory. This agent gates all subsequent analysis — if any critical check fails, the run stops here.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `path` | Repository root path |
| `compile_db` | Path to `compile_commands.json` |
| `config` | User config path (optional) |
| `languages` | Languages to analyze (e.g. `["c", "cpp", "rust"]`) |
| `max_tus` | Optional TU limit |
| `mcp_mode` | `off`, `prefer`, or `require` |
| `mcp_timeout_ms` | Timeout budget for MCP queries |
| `mcp_required_for_advanced` | Boolean — gates advanced findings on MCP availability |
| `enable_asm` | Boolean |
| `enable_semantic_ir` | Boolean |
| `enable_cfg` | Boolean |
| `enable_runtime_tests` | Boolean |
| `opt_levels` | Optimization levels (e.g. `["O0", "O1", "O2"]`) |
| `poc_categories` | Finding categories for PoC generation |
| `poc_output_dir` | Output directory for PoCs |
| `baseDir` | Plugin base directory |

## Process

### Step 1 — Create Work Directory

```bash
RUN_ID=$(python3 -c "import uuid; print(uuid.uuid4().hex[:12])")
WORKDIR="/tmp/zeroize-audit-${RUN_ID}"
mkdir -p "${WORKDIR}"/{mcp-evidence,source-analysis,compiler-analysis,rust-compiler-analysis,report,poc,tests,agent-inputs}
```

### Step 2 — Preflight Validation

Validate all prerequisites. Fail fast on the first failure; do not proceed with partial results.

**C/C++ mode** (when `compile_db` is provided):

1. Verify `compile_db` is provided and the file exists at the given path.
2. Verify at least one entry in the compile DB resolves to an existing source file and working directory.
3. Attempt a trial compilation of one representative TU using its captured flags to confirm the codebase is buildable.
4. Verify `{baseDir}/tools/extract_compile_flags.py` exists and is executable.
5. Verify `{baseDir}/tools/emit_ir.sh` exists and is executable.
6. If `enable_asm=true`: verify `{baseDir}/tools/emit_asm.sh` exists; if missing, set `enable_asm=false` and emit a warning.

**Rust mode** (when `cargo_manifest` is provided):

1. Verify `cargo_manifest` is provided and the file exists.
2. Verify `cargo +nightly` is on PATH; if absent, fail fast.
3. Verify `uv` is on PATH; if absent, fail fast.
4. Run `cargo +nightly check --manifest-path <cargo_manifest>` to confirm the crate builds.
5. Verify `{baseDir}/tools/emit_rust_mir.sh` exists and is executable; if absent, fail fast.
6. Verify `{baseDir}/tools/emit_rust_ir.sh` exists and is executable; if absent, fail fast.
7. If `enable_asm=true`: verify `{baseDir}/tools/emit_rust_asm.sh` exists; if missing, set `enable_asm=false` and emit a warning.
8. Verify required Python scripts exist: `semantic_audit.py`, `find_dangerous_apis.py`, `check_mir_patterns.py`, `check_llvm_patterns.py`, `check_rust_asm.py`. Warn for any missing script (analysis for that step is skipped; do not fail the entire run).

**Both modes**:

- If `mcp_mode != off`: run `{baseDir}/tools/mcp/check_mcp.sh` to probe MCP availability.
   - If `mcp_mode=require` and MCP is unreachable: **stop the run** and report the MCP failure.
   - If `mcp_mode=prefer` and MCP is unreachable: set `mcp_available=false`, continue.

Report each preflight failure with the specific check that failed and the remediation step.

### Step 3 — Load and Merge Configuration

Load `{baseDir}/configs/default.yaml` as the base configuration. If `config` is provided, merge the user config on top using key-level override semantics: user config values override individual keys in the default; any key not set in the user config falls back to the default value.

Write the merged config to `${WORKDIR}/merged-config.yaml`.

### Step 4 — Enumerate Translation Units

1. Parse `compile_db` and enumerate all translation units. Apply `max_tus` limit if set. Filter by `languages`.
2. Compute a hash of each source path to produce a `tu_hash` for collision-free parallel processing.
3. Run a lightweight grep across all TUs for sensitive name patterns (from merged config) to produce a `sensitive_candidates` list for the MCP resolver.

### Step 5 — Write Output Files

Write `${WORKDIR}/preflight.json`:

```json
{
  "run_id": "<RUN_ID>",
  "timestamp": "<ISO-8601>",
  "repo": "<path>",
  "compile_db": "<compile_db>",
  "opt_levels": ["O0", "O1", "O2"],
  "mcp_mode": "<mcp_mode>",
  "mcp_available": true,
  "enable_asm": true,
  "enable_semantic_ir": false,
  "enable_cfg": false,
  "enable_runtime_tests": false,
  "tu_count": 0,
  "tu_list": [{"file": "/path/to/file.c", "tu_hash": "a1b2c3d4"}],
  "sensitive_candidates": [{"name": "key", "file": "/path/to/file.c", "line": 42}]
}
```

Write `${WORKDIR}/orchestrator-state.json`:

```json
{
  "run_id": "<RUN_ID>",
  "workdir": "<WORKDIR>",
  "current_phase": 0,
  "inputs": {
    "path": "<path>",
    "compile_db": "<compile_db>",
    "mcp_mode": "<mcp_mode>",
    "mcp_required_for_advanced": false,
    "enable_asm": true,
    "enable_semantic_ir": false,
    "enable_cfg": false,
    "enable_runtime_tests": false,
    "opt_levels": ["O0", "O1", "O2"],
    "languages": ["c", "cpp", "rust"],
    "max_tus": null,
    "poc_categories": "all",
    "poc_output_dir": null
  },
  "routing": {
    "mcp_available": true,
    "tu_count": 0,
    "finding_count": 0
  },
  "phases": {
    "0": {"status": "complete", "output": "preflight.json"}
  },
  "key_file_paths": {
    "config": "merged-config.yaml",
    "preflight": "preflight.json",
    "state": "orchestrator-state.json"
  }
}
```

### Step 6 — Report Workdir

As your final output, include the workdir path prominently so the orchestrator can locate the state file:

```
Workdir: <WORKDIR>
```

## Error Handling

- **Any preflight check failure**: Write error details and stop. Do NOT write `orchestrator-state.json` (its absence signals failure to the orchestrator).
- **Config merge failure**: Stop immediately.
- **TU enumeration failure**: Stop immediately.
