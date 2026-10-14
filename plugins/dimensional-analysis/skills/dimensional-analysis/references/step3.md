# Phase 3: Dimension Propagation

Spawn `dimensional-analysis:dimension-propagator` agents to extend anchor annotations through arithmetic, function calls, and assignments. Propagators also report dimensional mismatches discovered during tracing.

For detailed dimensional algebra rules, see [references/dimension-algebra.md](dimension-algebra.md).

## Scope Source of Truth

Read `DIMENSIONAL_SCOPE.json` and build propagation batches from `in_scope_files`.

- Every file in `in_scope_files` must receive a Phase 3 outcome.
- MEDIUM/LOW priority files are required scope and cannot be skipped.

## Batching Strategy

Do not spawn one agent per file. Group files into batches and spawn one agent per batch:

- **≤ 10 files**: single batch, one agent handles all files.
- **11–30 files**: batch by category (one batch per category: math libraries, oracles, core logic, peripheral). Spawn agents in category order.
- **> 30 files**: same category-based batching, but split any category with more than 10 files into sub-batches of ~8 files each.

Within each batch, the agent processes files sequentially in the order listed.

## Propagation Order

Spawn batches in the recommended discovery order from Phase 1: math libraries first, then oracles, then core logic, then peripheral. Earlier batches establish annotations that later batches depend on — wait for each category to complete before spawning the next. Batches within the same category can run in parallel.

## Coverage Gate (Mandatory)

Before launching agents, confirm every file already has a non-pending Phase 2 status.

Then initialize Phase 3 tracking:

- `phase3 = "PENDING"` for every in-scope file.

After each propagator batch completes, update each assigned file to exactly one of:

- `PROPAGATED` — propagation annotations and/or mismatch analysis completed
- `REVIEWED_NO_PROPAGATION_CHANGES` — file reviewed and no additional propagation edits were needed
- `BLOCKED` — file could not be processed, with reason

Retry `BLOCKED` files once (with focused prompts). If a file remains `BLOCKED` after one retry, keep it as `BLOCKED` with a documented reason and proceed — include it in `coverage.unprocessed_files` in the final output. Do not proceed to Phase 4 while any file remains `PENDING`.

## What to Provide to Each Propagator Agent

Each `dimensional-analysis:dimension-propagator` spawn must include the following in its prompt:

1. **Path to `DIMENSIONAL_UNITS.md`** — the absolute path so the agent can read the vocabulary (base units, derived units, precision prefixes) itself.
2. **Path to `DIMENSIONAL_SCOPE.json`** — so the agent can cross-check scope metadata for assigned files.
3. **Assigned file paths** — the absolute file paths for this batch, in order.
4. **File categories and matched patterns** — from the scanner output (Phase 1), include each file's category (e.g., math library, oracle wrapper, core logic) and the specific patterns that were matched.
5. **Summary of anchor annotations from Phase 2** — summarize key annotations from the anchor phase: interface return types, constant dimensions, state variable dimensions. This gives the propagator its starting points for tracing data flow.
6. **Required per-file status output** — each file must end with `PROPAGATED`, `REVIEWED_NO_PROPAGATION_CHANGES`, or `BLOCKED` (with reason) and a one-line justification.

## Collecting Results

After all propagator agents complete, aggregate their reports:

1. **Total annotations added** — count across all files, broken down by confidence level (CERTAIN, INFERRED, UNCERTAIN).
2. **Mismatches found** — collect all mismatches with severity levels. These will be deduplicated against Phase 4 findings.
3. **Coverage gaps** — variables that could not be inferred. These inform where the validator should focus.

## Step Completion and Next Workflow File

Only continue when every file in `DIMENSIONAL_SCOPE.json.in_scope_files` has a non-pending Phase 3 status.

Read [references/step4.md](step4.md) next.
