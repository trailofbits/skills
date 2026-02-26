# Phase 1 — MCP Resolution and Source Analysis

## Preconditions

- Phase 0 complete: `orchestrator-state.json` exists with `phases.0.status = "complete"`
- `{workdir}/preflight.json` exists
- `{workdir}/merged-config.yaml` exists

## Instructions

### Wave 1 — MCP Resolver

Skip if `mcp_mode=off` or `routing.mcp_available=false` or `language_mode=rust` (MCP is C/C++ only).

Write agent inputs to `{workdir}/agent-inputs/mcp-resolver.json`:

```json
{
  "sensitive_candidates": "<from preflight.json sensitive_candidates>"
}
```

Spawn agent `1-mcp-resolver` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `repo_root` | `{{path}}` |
| `compile_db` | `{{compile_db}}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `input_file` | `{workdir}/agent-inputs/mcp-resolver.json` |
| `mcp_timeout_ms` | `{{mcp_timeout_ms}}` |

**After completion**: Read `{workdir}/mcp-evidence/status.json`.

- If `status=failed` and `mcp_mode=require`: **stop the run**.
- If `status=failed` and `mcp_mode=prefer`: set `mcp_available=false`.
- If `status=partial` or `status=success`: set `mcp_available=true`.

### Wave 2a — Source Analyzer (C/C++ only)

Skip if `language_mode=rust`.

Write agent inputs to `{workdir}/agent-inputs/source-analyzer.json`:

```json
{
  "tu_list": "<from preflight.json tu_list>"
}
```

Spawn agent `2-source-analyzer` via `Task` **in the same message as Wave 2b** (parallel launch):

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `repo_root` | `{{path}}` |
| `compile_db` | `{{compile_db}}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `input_file` | `{workdir}/agent-inputs/source-analyzer.json` |
| `mcp_available` | Result from Wave 1 |
| `languages` | `{{languages}}` |
| `max_tus` | `{{max_tus}}` |

### Wave 2b — Rust Source Analyzer (Rust only)

Skip if `language_mode=c`.

Spawn agent `2b-rust-source-analyzer` via `Task` **in the same message as Wave 2a** (parallel launch):

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `repo_root` | `{{path}}` |
| `cargo_manifest` | `{{cargo_manifest}}` |
| `rust_crate_root` | From `preflight.json` |
| `rust_tu_hash` | From `preflight.json` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `baseDir` | `{baseDir}` |

The `2b-rust-source-analyzer` agent must:

1. Attempt rustdoc JSON generation:
   ```bash
   cargo +nightly rustdoc --manifest-path <cargo_manifest> \
     --document-private-items -- -Z unstable-options --output-format json
   ```
   If this fails, warn and skip — proceed with source grep only.
2. Run semantic audit (if rustdoc JSON succeeded):
   ```bash
   uv run {baseDir}/tools/scripts/semantic_audit.py \
     --rustdoc target/doc/<crate>.json \
     --cargo-toml <cargo_manifest> \
     --out {workdir}/source-analysis/rust-semantic-findings.json
   ```
3. Run dangerous API scan:
   ```bash
   uv run {baseDir}/tools/scripts/find_dangerous_apis.py \
     --src <rust_crate_root>/src \
     --out {workdir}/source-analysis/rust-dangerous-api-findings.json
   ```
4. Merge outputs into `{workdir}/source-analysis/sensitive-objects.json` (Rust `SO-NNNN` IDs with offset 5000+), `{workdir}/source-analysis/source-findings.json` (IDs `F-RUST-SRC-NNNN`), and `{workdir}/source-analysis/tu-map.json` (adding `{"<cargo_manifest>": "<rust_tu_hash>"}`).
5. Write `{workdir}/source-analysis/rust-notes.md` summarizing findings and any skipped steps.

**After both Wave 2a and Wave 2b complete**: Read `{workdir}/source-analysis/tu-map.json`.

- If empty (`{}`): no sensitive objects found. Skip to Phase 6 (empty report).
- Determine entry classes in `tu-map.json`:
  - **C/C++ entry**: key is a source file path from `compile_commands.json` (typically `.c`, `.cc`, `.cpp`, `.cxx`).
  - **Rust entry**: key is the `cargo_manifest` path (`.../Cargo.toml`).
- If no C/C++ entries: skip Wave 3 in Phase 2.
- If no Rust entry: skip Wave 3R in Phase 2.
- Otherwise: proceed to Phase 2.

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 1,
  "routing": {
    "mcp_available": "<updated value>",
    "tu_count": "<count of TUs in tu-map.json>"
  },
  "phases": {
    "1": {"status": "complete", "output": "source-analysis/tu-map.json"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| MCP resolver fails + `mcp_mode=require` | Stop the run |
| MCP resolver fails + `mcp_mode=prefer` | Continue with `mcp_available=false` |
| Source analyzer (C/C++) fails | Stop C/C++ analysis — no sensitive object list for C/C++ TUs |
| Rust source analyzer fails | Stop Rust analysis — log failure, continue if C/C++ analysis is also running |
| No sensitive objects found | Skip Phases 2–5, jump to Phase 6 for empty report |

## Next Phase

Phase 2 — Compiler Analysis (if `tu-map.json` is non-empty)
