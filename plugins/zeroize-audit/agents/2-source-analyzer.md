---
name: 2-source-analyzer
description: "Identifies sensitive objects, detects wipe calls, validates correctness, and performs data-flow/heap analysis for zeroize-audit. Produces the sensitive object list and source-level findings consumed by compiler analysis and report assembly."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# 2-source-analyzer

Identify sensitive objects, detect wipes, validate correctness, and perform data-flow and heap analysis. Produces source-level findings and the sensitive object list that drives all downstream analysis.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `repo_root` | Repository root path |
| `compile_db` | Path to `compile_commands.json` |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `input_file` | Path to `{workdir}/agent-inputs/source-analyzer.json` containing `tu_list` |
| `mcp_available` | Boolean — whether MCP evidence exists in `{workdir}/mcp-evidence/` |
| `languages` | Languages to analyze (e.g. `["c", "cpp", "rust"]`) |
| `max_tus` | Optional TU limit |

## Process

### Step 0 — Load Configuration and Inputs

Read `config_path` to load the merged config (sensitive patterns, approved wipes, annotations). Read `input_file` to load `tu_list` (JSON array of `{file, tu_hash}`).

### Step 1 — Load MCP Evidence (if available)

If `mcp_available=true`, read:
- `{workdir}/mcp-evidence/symbols.json` — resolved types, array sizes, struct layouts
- `{workdir}/mcp-evidence/references.json` — cross-file reference graph

MCP-resolved type data takes precedence over source-level estimates for wipe-size validation and copy detection.

### Step 2 — Identify Sensitive Objects

Scan all TUs (up to `max_tus`) for objects matching heuristics from the merged config:

**Name patterns (low confidence):** Case-insensitive substring match: `key`, `secret`, `seed`, `priv`, `sk`, `shared_secret`, `nonce`, `token`, `pwd`, `pass`

**Type hints (medium confidence):** Byte buffers, fixed-size arrays, structs whose names or fields match name patterns.

**Explicit annotations (high confidence):** `__attribute__((annotate("sensitive")))`, `SENSITIVE` macro, Rust `#[secret]`, `Secret<T>` — configurable via merged config.

Cross-reference MCP-resolved type data from Step 1 where available.

Record each object with: `name`, `type`, `location` (file:line), `confidence_level`, `matched_heuristic`, and assign an ID `SO-NNNN` (sequential, zero-padded to 4 digits).

### Step 3 — Detect Wipe Calls

For each sensitive object, check for approved wipe calls within scope or reachable cleanup paths. Approved wipes come from the merged config; defaults include `explicit_bzero`, `memset_s`, `SecureZeroMemory`, `OPENSSL_cleanse`, `sodium_memzero`, `zeroize::Zeroize`, `Zeroizing<T>`, `ZeroizeOnDrop`, and volatile wipe loops.

Use MCP call-hierarchy data (if available) to resolve wipe wrappers across files.

### Step 4 — Validate Correctness

For each sensitive object with a detected wipe, validate:

- **Size correct**: Wipe length must match `sizeof(object)`, not `sizeof(pointer)` and not a partial length. MCP-resolved typedefs and array sizes take precedence. Emit `PARTIAL_WIPE` (ID: `F-SRC-NNNN`) if incorrect.
- **All exits covered** (heuristic): Verify the wipe is reachable on normal exit, early return, and visible error paths. Emit `NOT_ON_ALL_PATHS` if any path appears uncovered. Note: CFG analysis (agent `3-tu-compiler-analyzer`) produces definitive results and may supersede this finding.
- **Ordering correct**: Wipe must occur before `free()` or scope end. Emit `PARTIAL_WIPE` with ordering note if violated.

### Step 5 — Data-Flow and Heap Analysis

Use MCP cross-file references to extend tracking beyond the current TU where available.

**Data-flow (produces `SECRET_COPY`):**
- Detect `memcpy()`/`memmove()` copying sensitive buffers
- Track struct assignments and array copies
- Flag function arguments passed by value (copies on stack)
- Flag secrets returned by value
- Emit `SECRET_COPY` when any copy exists and no approved wipe tracks the destination

Optionally use `{baseDir}/tools/track_dataflow.sh` to assist with cross-function tracking.

**Heap (produces `INSECURE_HEAP_ALLOC`):**
- Detect `malloc`/`calloc`/`realloc` allocating sensitive objects
- Check for `mlock()`/`madvise(MADV_DONTDUMP)` — note absence as a warning
- Emit `INSECURE_HEAP_ALLOC` when standard allocators are used

Optionally use `{baseDir}/tools/analyze_heap.sh` to assist with heap analysis.

### Step 6 — Build TU Map

For each TU containing at least one sensitive object, record the mapping from source file path to `TU-{hash}` (hash provided by orchestrator in `tu_list`). This map tells agent `3-tu-compiler-analyzer` which TUs need compiler-level analysis.

## Output

Write all output files to `{workdir}/source-analysis/`:

| File | Content |
|---|---|
| `sensitive-objects.json` | Array of objects: `{id: "SO-NNNN", name, type, file, line, confidence, heuristic, has_wipe, wipe_api, wipe_location, related_findings: []}` |
| `source-findings.json` | Array of findings: `{id: "F-SRC-NNNN", category, severity, confidence, file, line, symbol, evidence: [], evidence_source: ["source"|"mcp"], related_objects: ["SO-NNNN"], related_findings: [], evidence_files: []}` |
| `tu-map.json` | `{"/path/to/file.c": "TU-a1b2c3d4", ...}` — only TUs with sensitive objects |
| `notes.md` | Human-readable summary: object counts by confidence, finding counts by category, MCP enrichment stats, relative paths to JSON files |

## Finding ID Convention

- Sensitive objects: `SO-NNNN` (e.g., `SO-0001`, `SO-0002`)
- Source findings: `F-SRC-NNNN` (e.g., `F-SRC-0001`, `F-SRC-0002`)

Sequential numbering within this agent run. Zero-padded to 4 digits.

## Error Handling

- **Always write `sensitive-objects.json`** — even if empty (`[]`). Downstream agents check this file to determine whether compiler analysis is needed.
- **Always write `source-findings.json`** — even if empty.
- **Always write `tu-map.json`** — even if empty (`{}`). An empty map signals no TUs need compiler analysis.
- If MCP evidence files are missing or malformed, continue without MCP enrichment and note in `notes.md`.

## Categories Produced

| Category | Severity |
|---|---|
| `MISSING_SOURCE_ZEROIZE` | medium |
| `PARTIAL_WIPE` | medium |
| `NOT_ON_ALL_PATHS` | medium |
| `SECRET_COPY` | high |
| `INSECURE_HEAP_ALLOC` | high |
