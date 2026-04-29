# MCP-Assisted Semantic Analysis

This reference covers how to configure, query, and interpret Serena MCP evidence during the zeroize-audit semantic pass. For compile DB generation and flag extraction, refer to the compile-commands reference (loaded separately from SKILL.md).

---

## Preconditions

Before running any MCP queries, the following must hold. These are verified during Step 1 (Preflight) in `task.md` — do not re-run preflight here, just confirm the relevant outputs:

| Precondition | Failure behavior |
|---|---|
| `compile_commands.json` valid and readable | Do not run MCP queries; fail the run if `mcp_mode=require` |
| Codebase buildable from compile DB commands | Same as above |
| `check_mcp.sh` exits 0 | If `mcp_mode=require`: stop run. If `mcp_mode=prefer`: set `mcp_available=false`, continue without MCP, apply confidence downgrades |
| Serena can resolve at least one symbol in the TU | Log a warning; proceed but mark findings from that TU as `needs_review` |

**Rust note**: Cargo does not natively produce `compile_commands.json`. Use `bear -- cargo build` or `bear -- cargo check` to generate it. `rust-project.json` is not a substitute in this workflow.

---

## Configuring Serena

The `plugin.json` registers Serena as the `serena` MCP server, launched via `uvx`. Serena wraps language servers (clangd for C/C++) and exposes semantic analysis as high-level MCP tools. It auto-discovers `compile_commands.json` from the project working directory.

**Prerequisites:**
- `uvx` must be on PATH (installed with `uv` — see https://docs.astral.sh/uv/)
- Serena is fetched and run automatically via `uvx --from git+https://github.com/oraios/serena`
- No separate `clangd` installation is required — Serena manages language server dependencies internally

**Verify before querying:**

```bash
{baseDir}/tools/mcp/check_mcp.sh \
  --compile-db /path/to/compile_commands.json
```

A non-zero exit means MCP is unreachable. Apply the preflight failure behavior above.

---

## MCP Tool Reference

Serena abstracts LSP methods into higher-level, symbol-name-based tools. Unlike raw LSP, you query by symbol name rather than file position.

| MCP tool name | Purpose in zeroize-audit | Key parameters |
|---|---|---|
| `activate_project` | **Must be called first.** Activates the project so Serena indexes it | `project` (path to repo root) |
| `find_symbol` | Resolve where a sensitive symbol is defined; get type info, body, and struct layout | `symbol_name`, `file_path` (optional), `include_body`, `depth` |
| `find_referencing_symbols` | Find all use sites and callers across files | `symbol_name`, `file_path` (optional) |
| `get_symbols_overview` | List all symbols in a file — useful for exploring unfamiliar TUs | `file_path` |

**Mapping from previous LSP-based queries:**

| Analysis need | Serena tool | Notes |
|---|---|---|
| Resolve definition | `find_symbol` | Search by name; returns file, line, kind, and optionally body |
| Find all references | `find_referencing_symbols` | Returns referencing symbols with file and line |
| Find callers (incoming calls) | `find_referencing_symbols` | Search for references to a function name |
| Find callees (outgoing calls) | `find_symbol` + source read | Get function body via `include_body: true`, then resolve called symbols |
| Resolve type / hover | `find_symbol` with `include_body: true` | Type information is included in the symbol result |
| Follow typedef chain | `find_symbol` | Look up the type name directly |

---

## Query Order

Run queries in this order so each step's output informs the next. All queries for a given TU should complete before moving to the next TU.

### Step 0 — Activate the project (`activate_project`)

This **must** be called once before any other Serena tool. Pass the repository root path. If activation fails, treat MCP as unavailable.

```
Tool: activate_project
Arguments:
  project: "/path/to/repo"
```

Expected: confirmation that the project is active. Serena will start indexing the codebase (including launching clangd if needed). Wait for activation to succeed before proceeding.

### Step 1 — Resolve symbol definition (`find_symbol`)

Establishes the canonical declaration location and type information used in all subsequent queries.

```
Tool: find_symbol
Arguments:
  symbol_name: "secret_key"
  include_body: true
```

Expected: result with `file`, `line`, `kind`, `symbol` name, and body content. The body provides type information (array sizes, struct layout) needed for wipe-size validation in Step 3. Store this as the canonical location for Steps 2–4.

If the symbol name is ambiguous, narrow with `file_path`:

```
Tool: find_symbol
Arguments:
  symbol_name: "secret_key"
  file_path: "src/crypto.c"
  include_body: true
```

### Step 2 — Collect all use sites (`find_referencing_symbols`)

Finds every location where the sensitive symbol is referenced. Use these to locate adjacent wipe calls and detect copies to other scopes.

```
Tool: find_referencing_symbols
Arguments:
  symbol_name: "secret_key"
```

Expected: list of referencing symbols with `file`, `line`, `symbol`, and `kind`. For each reference in a file other than the source TU, check that file for cleanup. References in generated files (build directory) can be filtered by source directory prefix.

### Step 3 — Resolve type and size

Type information is returned as part of `find_symbol` results (Step 1). If you need to resolve a typedef or follow a type alias chain, look up the type name directly:

```
Tool: find_symbol
Arguments:
  symbol_name: "secret_key_t"
  include_body: true
```

Use this to validate wipe sizes — a `sizeof(ptr)` bug will be apparent when the symbol body reveals `uint8_t [32]` but the wipe uses `sizeof(uint8_t *)`.

### Step 4 — Trace callers and cleanup paths

Use `find_referencing_symbols` on the function containing the sensitive object to find callers that may hold their own copy of the secret. Use it on wipe wrapper functions to find cleanup paths.

```
Tool: find_referencing_symbols
Arguments:
  symbol_name: "process_key"
```

For outgoing calls (what does this function call?), read the function body from `find_symbol` output and resolve each called function:

```
Tool: find_symbol
Arguments:
  symbol_name: "process_key"
  include_body: true
```

Then for each function called within the body:

```
Tool: find_symbol
Arguments:
  symbol_name: "cleanup_secret"
```

### Step 5 — Normalize output

Before using any MCP results in confidence scoring or finding emission, normalize:

```bash
python {baseDir}/tools/mcp/normalize_mcp_evidence.py \
  --input /tmp/raw_mcp_results.json \
  --output /tmp/normalized_mcp_results.json
```

The normalizer produces a consistent schema consumed by the MCP semantic pass and subsequent confidence gating steps.

---

## Interpreting Responses

| Response | Meaning | Action |
|---|---|---|
| Empty results | Serena could not resolve the symbol | Check compile DB path; verify symbol name spelling; retry with `file_path` to narrow scope |
| Timeout (> `mcp_timeout_ms`) | Query too slow | Mark finding as `needs_review`; do not wait indefinitely |
| Multiple results for same name | Symbol is defined in multiple TUs or headers | Use `file_path` to disambiguate; note in evidence |
| References in generated files | Hits in build-generated sources | Filter by source directory prefix |
| No referencing symbols found | Symbol is unused or not indexed | Acceptable for leaf functions; note in evidence |

---

## Confidence Scoring

MCP evidence contributes one signal toward the 2-signal threshold for `confirmed` findings (see SKILL.md Confidence Gating). Tag each piece of evidence with its source:

| Evidence source tag | Meaning |
|---|---|
| `mcp` | Resolved via Serena MCP query |
| `source` | Source-level pattern match |
| `ir` | LLVM IR analysis |
| `asm` | Assembly analysis |
| `cfg` | Control-flow graph analysis |

MCP evidence alone (1 signal) produces `likely`. MCP + one additional signal (source, IR, CFG, or ASM) produces `confirmed`.

**Mandatory downgrades** — applied by `apply_confidence_gates.py` after all evidence is collected:

| Condition | Findings downgraded to `needs_review` |
|---|---|
| `mcp_available=false` AND `mcp_required_for_advanced=true` | `SECRET_COPY`, `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS` (unless 2+ non-MCP signals exist) |
| Assembly evidence missing | `STACK_RETENTION`, `REGISTER_SPILL` |
| IR diff evidence missing | `OPTIMIZED_AWAY_ZEROIZE` |

Apply downgrades after all evidence is collected, not during querying. Do not suppress findings preemptively — emit at `needs_review` rather than dropping them.

---

## Post-Processing

After collecting all MCP evidence and running IR/ASM/CFG analysis, apply confidence gates mechanically:

```bash
python {baseDir}/tools/mcp/apply_confidence_gates.py \
  --input /tmp/raw-report.json \
  --out /tmp/final-report.json \
  --mcp-available \
  --mcp-required-for-advanced
```

Omit `--mcp-available` if MCP was unreachable. Omit `--mcp-required-for-advanced` if `mcp_required_for_advanced=false` in the run config. The script applies all downgrade rules from SKILL.md and outputs gated findings ready for the report assembly phase.
