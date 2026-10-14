# Phase 4: Bug Detection

Spawn `dimensional-analysis:dimension-validator` agents to detect dimensional bugs in annotated code, batching files as Phases 2-3 do.

For common bug patterns and examples, see [references/bug-patterns.md](bug-patterns.md).

For the standard DeFi dimensional vocabulary, see [references/common-dimensions.md](common-dimensions.md).

## File Selection

Validation targets are **all files in `DIMENSIONAL_SCOPE.json.in_scope_files`**.

Use this priority order, but do not skip lower tiers:

1. Files with CRITICAL/HIGH Phase 3 mismatches
2. Remaining CRITICAL/HIGH scanner-priority files
3. Remaining MEDIUM/LOW files

Every in-scope file must receive a validator outcome.

## Coverage Gate (Mandatory)

Before launching validators, confirm every file already has a non-pending Phase 3 status.

Then initialize Phase 4 tracking:

- `phase4 = "PENDING"` for every in-scope file.

After each validator batch completes, update each assigned file to exactly one of:

- `VALIDATED` — file fully reviewed (with or without findings)
- `BLOCKED` — file could not be validated, with reason

Retry `BLOCKED` files once (with focused prompts). If a file remains `BLOCKED` after one retry, keep it as `BLOCKED` with a documented reason — include it in `coverage.unprocessed_files` in the final output. Do not finalize while any file remains `PENDING`.

## Batching Strategy

Group files into batches and spawn one agent per batch, as Phases 2 and 3 do.
Batch by call-graph proximity: keep callers together with the files they call into,
so a single validator sees both sides of a cross-boundary dimension assumption
instead of a summarized signature. Cross-contract assumption mismatch is the first
entry in the Critical list below, and it is the class most often missed when caller
and callee are validated separately.

- **≤ 10 files**: single batch, one agent handles all files.
- **11–30 files**: one batch per category, with callers grouped alongside the files they depend on.
- **> 30 files**: same, splitting any category over 10 files into sub-batches of ~8.

Give a file its own batch when Phase 3 recorded coverage gaps for it — that is where
the dimensional story is unresolved and depth pays for itself.

Batches have no ordering dependency and can all run in parallel. Do not terminate
early; continue until every in-scope file has a validator outcome.

## What to Provide to Each Validator Agent

Each `dimensional-analysis:dimension-validator` spawn must include the following in its prompt:

1. **Path to `DIMENSIONAL_UNITS.md`** — the absolute path so the agent can read the vocabulary (base units, derived units, precision prefixes) itself.
2. **Path to `DIMENSIONAL_SCOPE.json`** — so the validator can confirm this file is in scope and return a deterministic status.
3. **Assigned file paths** — the absolute paths in this batch, in order.
4. **All annotations in the assigned files** — both anchor annotations (from Phase 2) and propagated annotations (from Phase 3). The agent will re-read the files, but summarizing annotations gives it a head start and ensures it doesn't miss any.
5. **Phase 3 mismatches for the assigned files** — include CRITICAL/HIGH/MEDIUM findings, with mismatch IDs (e.g., MISMATCH-001). The validator uses these to confirm or refute each finding and to avoid duplicate reporting.
6. **Cross-file context for callees outside the batch** — annotated function signatures the assigned files call into: function name, parameter dimensions, and return dimensions. Files inside the batch need no summary; the validator reads them directly.
7. **Required per-file status output** — return `VALIDATED` (even when there are zero findings) or `BLOCKED` (with reason).

## Deduplication

Phase 3 mismatches that the validator confirms should not be reported as new findings. Instead, the validator notes confirmation inline:

```text
Confirmed: MISMATCH-001 from propagation — dimension mismatch at Folio.sol:456 verified.
```

Only genuinely new findings discovered during validation get new DIM-XXX IDs. This prevents the final report from listing the same issue twice under different identifiers.

If the validator refutes a Phase 3 mismatch (determines it was a false positive), it should note:

```text
Refuted: MISMATCH-003 from propagation — false positive, see analysis below.
```

## Collecting Results

After all validator agents complete, aggregate their reports:

1. **Confirmed Phase 3 findings** — mismatches from propagation that validators verified. These keep their original severity.
2. **New findings** — bugs discovered during validation that Phase 3 did not catch. Each gets a new DIM-XXX ID.
3. **Refuted findings** — Phase 3 mismatches that validators determined were false positives. These are excluded from the final count but noted for transparency.
4. **Coverage summary** — total functions analyzed, expressions checked, annotations used, and files validated.
5. **Unvalidated files** — must be empty (no `PENDING` files) before final output. Files that remain `BLOCKED` after retry are listed in `coverage.unprocessed_files`.

## Bug Categories

**Critical (P0)**:
- Dimension mismatch in assignment (LHS != RHS)
- Missing scaling factor
- Adding/subtracting incompatible dimensions
- Cross-contract dimension assumption mismatch

**High (P1)**:

- Wrong scaling direction (multiply vs divide)
- Inconsistent return path dimensions
- Wrong precision causing overflow/underflow

**Medium (P2)**:
- Implicit dimension cast
- Unused scaling factor
- Redundant precision conversion

## Output Format

Present findings as:

```text
## Dimensional Analysis Findings

### Critical Issues

#### DIM-001: Dimension Mismatch in Assignment
**Location:** Folio.sol:456
**Severity:** CRITICAL

uint256 price = oracle.getPrice(token); // Missing D9 scaling
Expected: D27{UoA/tok}
Actual: D18{UoA/tok}

**Root Cause:** Oracle returns D18 but code expects D27
**Recommendation:** Scale the oracle price: `oracle.getPrice(token) * 1e9`

### Summary
- Critical: 1
- High: 0
- Medium: 2
- Total: 3 findings
```

## References Used in This Phase

- [references/bug-patterns.md](bug-patterns.md) - Common dimensional bug patterns
- [references/common-dimensions.md](common-dimensions.md) - Standard DeFi dimension vocabulary
- [references/dimension-algebra.md](dimension-algebra.md) - Detailed rules for dimensional arithmetic

## Step Completion and Finalization

Only continue when every file in the `in_scope_files` array of `DIMENSIONAL_SCOPE.json` has a non-pending Phase 4 status.

After completing this phase, produce final output using the "Final Output" section of [SKILL.md](../SKILL.md).
