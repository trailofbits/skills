---
name: 4-report-assembler
description: "Collects all findings from source and compiler analysis, applies supersessions and confidence gates, normalizes IDs, and produces a comprehensive markdown report with structured JSON for downstream tools. Supports dual-mode invocation: interim (findings.json only) and final (merge PoC results, produce final-report.md)."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# 4-report-assembler

Collect all findings from source and compiler analysis phases, apply supersessions and confidence gates, normalize finding IDs to `ZA-NNNN`, and produce structured findings and a comprehensive markdown report. This agent is invoked twice: once in interim mode (findings only) and once in final mode (merge PoC results and produce the report).

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `mcp_available` | Boolean — whether MCP was successfully used |
| `mcp_required_for_advanced` | Boolean — gates advanced findings on MCP availability |
| `baseDir` | Plugin base directory (for tool and schema paths) |
| `mode` | `interim` or `final` — controls which steps execute and which outputs are produced |
| `poc_results` | Path to `poc_final_results.json` (final mode only) |

## Mode Branching

- **`interim` mode**: Execute Steps 1–5. Write `findings.json` only. Do **not** produce `final-report.md`.
- **`final` mode**: Read existing `findings.json`, execute Step 5b (merge PoC results), then produce both an updated `findings.json` and `final-report.md` (Step 6).

## Process

### Step 0 — Load Configuration

Read `config_path` to load the merged config (confidence gate thresholds, severity rules, report settings).

### Step 1 — Collect All Findings

Read finding files from the working directory:

1. **Source findings**: `{workdir}/source-analysis/source-findings.json`
2. **Compiler findings (C/C++)**: For each subdirectory in `{workdir}/compiler-analysis/*/`:
   - `ir-findings.json`
   - `asm-findings.json`
   - `cfg-findings.json`
   - `semantic-ir.json`
3. **Compiler findings (Rust)**: Read from `{workdir}/rust-compiler-analysis/`:
   - `mir-findings.json`
   - `ir-findings.json`
   - `asm-findings.json`
   - `cfg-findings.json`
   - `semantic-ir.json`
4. **Sensitive objects**: `{workdir}/source-analysis/sensitive-objects.json`
5. **MCP status**: `{workdir}/mcp-evidence/status.json` (if exists)
6. **Preflight metadata**: `{workdir}/preflight.json`

Merge all findings into a single list. Handle missing directories gracefully — a TU's `compiler-analysis/<tu_hash>/` directory or `rust-compiler-analysis/` may be absent if that agent failed.

Merge all findings into a single list. Handle missing directories gracefully — a TU's compiler-analysis directory may be absent if that agent failed.

### Step 2 — Apply Supersessions

Read `superseded-findings.json` from:
- each C/C++ compiler-analysis subdirectory (`{workdir}/compiler-analysis/*/superseded-findings.json`)
- Rust compiler analysis (`{workdir}/rust-compiler-analysis/superseded-findings.json`)

For each supersession:
- Remove the superseded finding (e.g., `F-SRC-0005` for `NOT_ON_ALL_PATHS`)
- Keep the superseding finding (e.g., `F-CFG-a1b2-0003` for `NOT_DOMINATING_EXITS` or `MISSING_ON_ERROR_PATH`)
- Record the supersession in `notes.md`

### Step 3 — Apply Confidence Gates

Apply the confidence gating rules from the SKILL.md. Optionally use the mechanical enforcer:

```bash
python {baseDir}/tools/mcp/apply_confidence_gates.py \
  --findings <raw_findings_json> \
  --mcp-available <mcp_available> \
  --mcp-required-for-advanced <mcp_required_for_advanced>
```

**Key rules (authoritative version in SKILL.md):**

- A finding needs 2+ independent signals to be `confirmed`; 1 signal -> `likely`; 0 strong signals -> `needs_review`.
- `OPTIMIZED_AWAY_ZEROIZE` requires IR diff evidence. Never emit from source alone.
- `STACK_RETENTION` and `REGISTER_SPILL` require assembly evidence. Never emit from source or IR alone.
- If `mcp_available=false` and `mcp_required_for_advanced=true`: downgrade `SECRET_COPY`, `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS` to `needs_review` unless 2+ non-MCP signals exist.
- If a rationalization override was attempted, retain the finding and note in evidence.

### Step 4 — Normalize IDs

Assign final `ZA-NNNN` IDs (sequential, zero-padded to 4 digits) to all surviving findings. Record the mapping from namespaced IDs to final IDs in `id-mapping.json`.

Ordering:
- C/C++ source findings first (by `F-SRC-NNNN` order)
- Rust source findings next (by `F-RUST-SRC-NNNN` order)
- C/C++ compiler findings grouped by TU (sorted by TU hash, then by finding type: IR, ASM, CFG, SIR)
- Rust compiler findings last (ordered by finding type: MIR, IR, ASM)

### Step 5 — Produce Structured Findings JSON

Write `findings.json` — a structured JSON file consumed by downstream agents (`5-poc-generator`, `6-test-generator`). This file matches `{baseDir}/schemas/output.json`:

```json
{
  "run_id": "<from preflight.json>",
  "timestamp": "<ISO-8601>",
  "repo": "<path>",
  "findings": [],
  "summary": {
    "total": 0,
    "by_severity": {},
    "by_category": {},
    "by_confidence": {}
  }
}
```

Each finding includes:

| Field | Content |
|---|---|
| `id` | `ZA-NNNN` |
| `category` | Finding category enum |
| `severity` | `high` or `medium` |
| `confidence` | `confirmed`, `likely`, or `needs_review` |
| `location` | `{file, line}` |
| `object` | `{name, type, size_bytes}` |
| `evidence` | Array of evidence objects `{source, detail}` |
| `evidence_source` | Tags: `source`, `mcp`, `ir`, `asm`, `cfg` |
| `compiler_evidence` | IR/ASM evidence details (if applicable) |
| `fix` | Recommended remediation |
| `poc` | PoC object with `validated: false`, `validation_result: "pending"` (interim mode) |

Before writing `findings.json`, validate cross-references:
- Every `related_objects` entry must exist in `sensitive-objects.json`.
- If a reference is missing, keep the finding but add a warning note in `notes.md` and append an evidence note (e.g., `[assembler] related object SO-5xxx missing in sensitive-objects.json`).

**In interim mode, stop here.** Do not produce `final-report.md`.

### Step 5b — Merge PoC Validation and Verification Results (final mode only)

Read `poc_results` (path to `poc_final_results.json`). This file contains both runtime validation results (compile/run) and semantic verification results (does the PoC prove its claim?). For each entry, match to a finding by `finding_id` and update the finding's `poc` object:

| PoC Result | Finding Update |
|---|---|
| `exit_code=0`, `verified=true` (exploitable, verified) | Set `poc.validated=true`, `poc.verified=true`, `poc.validation_result="exploitable"`. Add evidence note: "PoC confirmed: secret persists after operation (exit code 0). Verification passed." Count as a confidence signal — can upgrade `likely` to `confirmed`. |
| `exit_code=1`, `verified=true` (not exploitable, verified) | Set `poc.validated=true`, `poc.verified=true`, `poc.validation_result="not_exploitable"`. Downgrade severity to `"low"` (informational). Add evidence note: "PoC disproved: secret was wiped (exit code 1). Verification passed." |
| `verified=false`, user accepted | Set `poc.validated=true`, `poc.verified=false`. Use the PoC's original `validation_result`. Add evidence note: "PoC verification failed but user accepted result. Checks: {list failed checks}." Treat as a weaker confidence signal than a verified PoC. |
| `verified=false`, user rejected (`"rejected"`) | Set `poc.validated=false`, `poc.verified=false`, `poc.validation_result="rejected"`. Add evidence note: "PoC verification failed and user rejected result. Checks: {list failed checks}." No confidence change. |
| Compile failure | Set `poc.validated=false`, `poc.validation_result="compile_failure"`. Add evidence note: "PoC compilation failed". No confidence change. |
| No PoC generated | Set `poc.validated=false`, `poc.validation_result="no_poc"`. Add evidence note: "No PoC generated for this finding". No confidence change. |

After merging, compute the `poc_validation_summary` for the top-level summary:
```json
{
  "total_findings": 0,
  "pocs_generated": 0,
  "pocs_validated": 0,
  "pocs_verified": 0,
  "exploitable_confirmed": 0,
  "not_exploitable": 0,
  "rejected": 0,
  "compile_failures": 0,
  "no_poc_generated": 0,
  "verification_failures": 0
}
```

Write the updated `findings.json` with merged PoC data.

### Step 6 — Produce Final Markdown Report

Write `final-report.md` — the primary human-readable output. Use the template at `{baseDir}/prompts/report_template.md` as a structural guide. The report must be comprehensive and self-contained.

**Required sections:**

#### Header
- Report title: `# Zeroize Audit Report`
- Run metadata: run_id, timestamp, repository path, compile_db path
- Configuration summary: opt_levels, mcp_mode, enabled analyses (asm, semantic_ir, cfg, runtime_tests), PoC validation status

#### Executive Summary
- Total findings count
- Breakdown by severity (table: high / medium / low)
- Breakdown by confidence (table: confirmed / likely / needs_review)
- Breakdown by category (table with counts per finding type)
- MCP availability status and impact on findings
- PoC validation summary counts

#### Sensitive Objects Inventory
- Table of all sensitive objects identified: ID, name, type, file:line, confidence, heuristic matched
- Note which objects have approved wipes and which do not

#### Findings (grouped by severity, then confidence)

For each finding, render a subsection:

```markdown
### ZA-NNNN: CATEGORY — severity (confidence)

**Location:** `file.c:123`
**Object:** `key` (`uint8_t[32]`, 32 bytes)

**Evidence:**
- [source] Description of source-level evidence
- [ir] Description of IR-level evidence
- [asm] Description of assembly-level evidence

**Compiler Evidence** (if applicable):
- Opt levels analyzed: O0, O1, O2
- O0: wipe present — `llvm.memset(key, 0, 32)` at line 88
- O2: wipe absent — dead-store elimination after SROA
- Summary: Wipe first disappears at O2. Non-volatile memset eliminated by DSE.

**PoC Validation:** exploitable / not_exploitable / rejected / compile_failure / no_poc / pending
- Exit code: N
- PoC file: poc_za_0001_category.c
- Verified: yes / no (if no: {list failed checks})

**Recommended Fix:**
Use `explicit_bzero(key, sizeof(key))` on all exit paths.
```

#### PoC Validation Results

Table between Findings and Superseded Findings:

```markdown
| Finding | Category | PoC File | Exit Code | Result | Verified | Impact |
|---|---|---|---|---|---|---|
| ZA-0001 | MISSING_SOURCE_ZEROIZE | poc_za_0001.c | 0 | exploitable | Yes | Confirmed |
| ZA-0002 | STACK_RETENTION | poc_za_0002.c | 1 | not_exploitable | Yes | Downgraded to low |
| ZA-0003 | OPTIMIZED_AWAY_ZEROIZE | poc_za_0003.c | 1 | rejected | No | Rejected — wrong opt level |
```

#### Superseded Findings
- List any source-level findings that were superseded by CFG analysis, with explanation

#### Confidence Gate Summary
- List any findings that were downgraded and why (e.g., MCP unavailable, missing hard evidence, PoC disproved)
- List any override attempts that were rejected

#### Analysis Coverage
- TUs analyzed vs. total TUs in compile DB
- Agents that ran successfully vs. failed
- Features enabled/disabled and their impact
- Agent 5 (PoC generator) status: success / failed

#### Appendix: Evidence Files
- Table mapping finding IDs to evidence file paths (relative to workdir) for auditor reference

## Output

Write all output files to `{workdir}/report/`:

| File | Content |
|---|---|
| `raw-findings.json` | All findings pre-gating, with original namespaced IDs |
| `id-mapping.json` | `{"F-SRC-0001": "ZA-0001", "F-IR-a1b2-0001": "ZA-0002", ...}` |
| `findings.json` | Gated findings in structured JSON matching `{baseDir}/schemas/output.json` (consumed by downstream agents) |
| `final-report.md` | Comprehensive markdown report — **final mode only** |
| `notes.md` | Assembly process: findings collected, supersessions applied, gates applied, IDs mapped, PoC results merged. Relative paths to all files. |

## Error Handling

- **Missing source-findings.json**: Fatal — source analysis must have run. Write error report.
- **Missing compiler-analysis directories**: Non-fatal. Produce report from available findings. Note missing TUs in the report's Analysis Coverage section.
- **Missing MCP evidence**: Non-fatal. Apply MCP-unavailable downgrades. Note in report.
- **Malformed finding JSON**: Skip the malformed entry, log in `notes.md`, continue.
- **Missing poc_results in final mode**: Non-fatal. Set all findings to `poc.validated=false`, `poc.verified=false`, `poc.validation_result="no_poc"`. Note in report.
- **Always produce `findings.json`** — even if it contains zero findings. An empty report should still have all sections with zero counts.
- **`final-report.md` is only produced in final mode.**

## Cross-Reference Convention

This agent consumes IDs from all upstream agents and produces the final `ZA-NNNN` namespace:

| Input ID Pattern | Source Agent |
|---|---|
| `SO-NNNN` | 2-source-analyzer |
| `SO-5NNN` | 2b-rust-source-analyzer |
| `F-SRC-NNNN` | 2-source-analyzer |
| `F-RUST-SRC-NNNN` | 2b-rust-source-analyzer |
| `F-IR-{tu_hash}-NNNN` | 3-tu-compiler-analyzer |
| `F-ASM-{tu_hash}-NNNN` | 3-tu-compiler-analyzer |
| `F-CFG-{tu_hash}-NNNN` | 3-tu-compiler-analyzer |
| `F-SIR-{tu_hash}-NNNN` | 3-tu-compiler-analyzer |
| `F-RUST-MIR-NNNN` | 3b-rust-compiler-analyzer |
| `F-RUST-IR-NNNN` | 3b-rust-compiler-analyzer |
| `F-RUST-ASM-NNNN` | 3b-rust-compiler-analyzer |
| `ZA-NNNN` | **This agent** (final output) |
