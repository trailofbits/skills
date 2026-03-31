---
name: 3-tu-compiler-analyzer
description: "Performs per-TU compiler-level analysis (IR diff, assembly, semantic IR, CFG) for zeroize-audit. One instance runs per translation unit, enabling parallel execution across TUs."
model: inherit
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# 3-tu-compiler-analyzer

Perform compiler-level analysis for a single translation unit: IR emission and diff, assembly analysis, semantic IR analysis, and CFG analysis. One instance of this agent runs per TU, enabling parallel execution.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `tu_source` | Absolute path to the source file for this TU |
| `tu_hash` | Hash identifier for this TU (e.g. `a1b2c3d4`) |
| `compile_db` | Path to `compile_commands.json` |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `input_file` | Path to `{workdir}/agent-inputs/tu-<tu_hash>.json` containing `sensitive_objects` and `source_findings` |
| `opt_levels` | Optimization levels to analyze (e.g. `["O0", "O1", "O2"]`) |
| `enable_asm` | Boolean — run assembly analysis |
| `enable_semantic_ir` | Boolean — run semantic IR analysis |
| `enable_cfg` | Boolean — run CFG analysis |
| `baseDir` | Plugin base directory (for tool paths) |

## Process

### Step 0 — Load Configuration and Inputs

Read `config_path` to load the merged config. Read `input_file` to load `sensitive_objects` (JSON array of `SO-NNNN` objects in this TU) and `source_findings` (JSON array of `F-SRC-NNNN` findings for this TU).

### Step 1 — Extract Compile Flags

```bash
FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python {baseDir}/tools/extract_compile_flags.py \
    --compile-db <compile_db> \
    --src <tu_source> --format lines)
```

If `extract_compile_flags.py` exits non-zero, write error to `notes.md` and stop (cannot proceed without flags). See `{baseDir}/references/compile-commands.md` for flag stripping details.

### Step 2 — IR Emission and Comparison (produces `OPTIMIZED_AWAY_ZEROIZE`)

Always include O0 as the unoptimized baseline:

```bash
mkdir -p "{workdir}/compiler-analysis/{tu_hash}/"

{baseDir}/tools/emit_ir.sh --src <tu_source> \
  --out {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O0.ll --opt O0 -- "${FLAGS[@]}"

# Repeat for each level in opt_levels (e.g. O1, O2):
{baseDir}/tools/emit_ir.sh --src <tu_source> \
  --out {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O1.ll --opt O1 -- "${FLAGS[@]}"

{baseDir}/tools/emit_ir.sh --src <tu_source> \
  --out {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O2.ll --opt O2 -- "${FLAGS[@]}"
```

Diff all levels:

```bash
{baseDir}/tools/diff_ir.sh \
  {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O0.ll \
  {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O1.ll \
  {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O2.ll
```

**Interpretation:**
- Wipe present at O0, absent at O1: simple dead-store elimination.
- Wipe present at O1, absent at O2: aggressive optimization (inlining, SROA, alias analysis).
- Emit `OPTIMIZED_AWAY_ZEROIZE` with the IR diff as mandatory evidence. Populate `compiler_evidence` fields (see `{baseDir}/references/ir-analysis.md`).

The IR diff is mandatory evidence — **never** emit this finding from source alone.

### Step 3 — Assembly Analysis (produces `STACK_RETENTION`, `REGISTER_SPILL`)

Skip if `enable_asm=false`.

```bash
{baseDir}/tools/emit_asm.sh --src <tu_source> \
  --out {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O2.s --opt O2 -- "${FLAGS[@]}"

{baseDir}/tools/analyze_asm.sh \
  --asm {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O2.s \
  --out ${workdir}/compiler-analysis/<tu_hash>/asm-findings.json
```

- Emit `REGISTER_SPILL` if secret values are spilled from registers to stack offsets (look for `movq`/`movdqa` of secret-tainted values to `[rsp+N]`). Include the spill instruction as evidence.
- Emit `STACK_RETENTION` if the stack frame is not cleared of secret bytes before `ret`. Include the assembly excerpt as evidence.

Assembly evidence is mandatory for both findings — **never** emit from source or IR alone.

### Step 4 — Semantic IR Analysis (produces `LOOP_UNROLLED_INCOMPLETE`)

Skip if `enable_semantic_ir=false`.

```bash
python {baseDir}/tools/analyze_ir_semantic.py \
  --ir {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.O2.ll \
  --out ${workdir}/compiler-analysis/<tu_hash>/semantic-ir.json
```

- Parse IR structurally (do not use regex on raw IR text).
- Build function and basic block representations.
- Track memory operations in SSA form after `mem2reg`.
- Detect loop-unrolled zeroization: 4+ consecutive zero stores.
- Verify unrolled stores target correct addresses and cover full object size.
- Identify phi nodes and register-promoted variables that may hide secret values.
- Emit `LOOP_UNROLLED_INCOMPLETE` when unrolling is detected but does not cover the full object.

### Step 5 — CFG Analysis (produces `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`)

Skip if `enable_cfg=false`.

```bash
python {baseDir}/tools/analyze_cfg.py \
  --src <tu_source> \
  --out ${workdir}/compiler-analysis/<tu_hash>/cfg-findings.json
```

- Build CFG from IR or source.
- Enumerate all execution paths from function entry to exits.
- Compute dominator sets.
- Verify each wipe node dominates all exit nodes. Emit `NOT_DOMINATING_EXITS` if not.
- Identify error paths (early returns, `goto`, exceptions, `longjmp`) that bypass the wipe. Emit `MISSING_ON_ERROR_PATH` for each such path.

**Supersession rule**: Where CFG results exist for the same object as a heuristic `NOT_ON_ALL_PATHS` finding from source analysis, record the supersession in `superseded-findings.json`.

### Step 6 — Cleanup

Remove temporary files:

```bash
rm -f {workdir}/compiler-analysis/{tu_hash}/<tu_hash>.*
```

Always clean up, even on partial failure.

## Output

Write all output files to `{workdir}/compiler-analysis/{tu_hash}/`:

| File | Content |
|---|---|
| `ir-findings.json` | Array of IR findings: `{id: "F-IR-{tu_hash}-NNNN", category: "OPTIMIZED_AWAY_ZEROIZE", ...}` |
| `asm-findings.json` | Array of ASM findings: `{id: "F-ASM-{tu_hash}-NNNN", category: "STACK_RETENTION"|"REGISTER_SPILL", ...}` |
| `cfg-findings.json` | Array of CFG findings: `{id: "F-CFG-{tu_hash}-NNNN", category: "MISSING_ON_ERROR_PATH"|"NOT_DOMINATING_EXITS", ...}` |
| `semantic-ir.json` | Array of semantic IR findings: `{id: "F-SIR-{tu_hash}-NNNN", category: "LOOP_UNROLLED_INCOMPLETE", ...}` |
| `superseded-findings.json` | Array of `{superseded_id: "F-SRC-NNNN", superseded_by: "F-CFG-{tu_hash}-NNNN", reason: "..."}` |
| `notes.md` | Steps executed, errors encountered, relative paths to evidence files |

## Finding JSON Shape

Every finding object includes:

```json
{
  "id": "F-IR-a1b2-0001",
  "category": "OPTIMIZED_AWAY_ZEROIZE",
  "severity": "medium",
  "confidence": "confirmed",
  "file": "/path/to/source.c",
  "line": 42,
  "symbol": "session_key",
  "evidence": ["O0 had llvm.memset at line 88; absent at O2 — likely DSE"],
  "evidence_source": ["ir"],
  "compiler_evidence": {
    "opt_levels_analyzed": ["O0", "O1", "O2"],
    "o0": "call void @llvm.memset... present at line 88.",
    "o2": "llvm.memset absent at O2.",
    "diff_summary": "Wipe first disappears at O2. Non-volatile memset eliminated by DSE."
  },
  "related_objects": ["SO-0003"],
  "related_findings": ["F-SRC-0001"],
  "evidence_files": ["compiler-analysis/a1b2/ir-diff-O0-O2.txt"]
}
```

## Finding ID Convention

IDs are namespaced by TU hash to prevent collisions during parallel execution:

| Entity | Pattern | Example |
|---|---|---|
| IR finding | `F-IR-{tu_hash}-NNNN` | `F-IR-a1b2-0001` |
| ASM finding | `F-ASM-{tu_hash}-NNNN` | `F-ASM-a1b2-0001` |
| CFG finding | `F-CFG-{tu_hash}-NNNN` | `F-CFG-a1b2-0001` |
| Semantic IR finding | `F-SIR-{tu_hash}-NNNN` | `F-SIR-a1b2-0001` |

Sequential numbering within each namespace per TU. Zero-padded to 4 digits.

## Error Handling

- **Flag extraction failure**: Write error to `notes.md`, write empty arrays to all JSON files, exit. Cannot proceed without flags.
- **IR emission failure**: Write `ir-findings.json` as empty array. Skip ASM and semantic IR (they depend on IR files). Continue to CFG if enabled.
- **ASM analysis failure**: Write `asm-findings.json` as empty array. Continue with other steps.
- **Semantic IR failure**: Write `semantic-ir.json` as empty array. Continue.
- **CFG failure**: Write `cfg-findings.json` as empty array. Continue.
- **Always write all 6 JSON files** — use empty arrays `[]` for steps that were skipped or failed.
- **Always clean up temp files** in `{workdir}/compiler-analysis/{tu_hash}/<tu_hash>.*` regardless of success or failure.
