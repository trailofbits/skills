---
name: 1-mcp-resolver
description: "Resolves symbol definitions, types, and cross-file references using Serena MCP for zeroize-audit. Runs before source analysis so enriched type data is available for wipe validation."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
  - mcp__serena__activate_project
  - mcp__serena__find_symbol
  - mcp__serena__find_referencing_symbols
  - mcp__serena__get_symbols_overview
---

# 1-mcp-resolver

Resolve symbol definitions, types, and cross-file references via Serena MCP before source analysis begins.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `repo_root` | Repository root path |
| `compile_db` | Path to `compile_commands.json` |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `input_file` | Path to `{workdir}/agent-inputs/mcp-resolver.json` containing `sensitive_candidates` |
| `mcp_timeout_ms` | Timeout budget for all MCP queries |

## Process

### Step 0 — Load Configuration and Inputs

Read `config_path` to load the merged config (sensitive patterns, approved wipes). Read `input_file` to load `sensitive_candidates` (JSON array of `{name, file, line}`).

### Step 1 — Activate Project

Call `activate_project` with `repo_root`. This **must** succeed before any other Serena tool.

```
Tool: activate_project
Arguments:
  project: "<repo_root>"
```

If activation fails, write `status.json` with `"status": "failed"` and stop.

### Step 2 — Resolve Symbols

For each candidate in `sensitive_candidates`:

1. **Resolve definition and type**: `find_symbol` with `symbol_name` and `include_body: true`. Record file, line, kind, type info, array sizes, and struct layout.
2. **Collect use sites**: `find_referencing_symbols` with `symbol_name`. Record all cross-file references.
3. **Trace wipe wrappers**: For any detected wipe function, use `find_referencing_symbols` to find callers. Read function bodies via `find_symbol` with `include_body: true` and resolve called symbols.
4. **Survey unfamiliar TUs**: Use `get_symbols_overview` when needed.

Respect `mcp_timeout_ms` — if the budget is exhausted, stop querying and write partial results.

### Step 3 — Build Reference Graph

From the collected results, build:
- A symbol-keyed map of definitions with resolved types
- A cross-file reference graph (caller -> callee relationships)
- Wipe wrapper chains (function A calls B which calls explicit_bzero)

### Step 4 — Normalize Evidence

Pipe all raw MCP output through the normalizer:

```bash
python {baseDir}/tools/mcp/normalize_mcp_evidence.py \
  --input <raw_results> \
  --output <workdir>/mcp-evidence/symbols.json
```

For Serena tool parameters, query patterns, and empty-response troubleshooting, see `{baseDir}/references/mcp-analysis.md`.

## Output

Write all output files to `{workdir}/mcp-evidence/`:

| File | Content |
|---|---|
| `status.json` | `{"status": "success|partial|failed", "symbols_resolved": N, "references_found": N, "errors": [...]}` |
| `symbols.json` | Normalized symbol definitions keyed by name: `{name, file, line, kind, type, body, array_size, struct_fields}` |
| `references.json` | Cross-file reference graph: `{symbol: [{file, line, kind, referencing_symbol}]}` |
| `notes.md` | Human-readable observations, unresolved symbols, and relative paths to JSON files |

## Error Handling

- **Activation failure**: Write `status.json` with `"status": "failed"`, exit. The orchestrator will set `mcp_available=false`.
- **Timeout**: Write partial results. Set `status.json` to `"status": "partial"` with the count of resolved vs. total candidates.
- **Individual query failure**: Log the error, skip the symbol, continue with others. Record skipped symbols in `status.json.errors`.
- **Always write `status.json`** — even on total failure, so downstream agents can check MCP availability.

## Cross-Reference Convention

This agent does not assign finding IDs. It produces evidence consumed by `2-source-analyzer` and `3-tu-compiler-analyzer`. Evidence files use relative paths from `{workdir}` (e.g., `mcp-evidence/symbols.json`).
