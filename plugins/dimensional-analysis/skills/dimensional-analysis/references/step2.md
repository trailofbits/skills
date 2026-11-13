# Phase 2: Anchor Annotation

Spawn `dimensional-analysis:dimension-annotator` agents to add dimensional annotations at high-confidence anchor points.

## Scope Source of Truth

Read `DIMENSIONAL_SCOPE.json` and build batches from `in_scope_files`. Do not derive scope from discoverer-only inputs.

- Every file in `in_scope_files` must receive a Phase 2 outcome.
- MEDIUM/LOW priority files are required scope and cannot be skipped.

## Batching Strategy

Do not spawn one agent per file. Group files into batches and spawn one agent per batch:

- **≤ 10 files**: single batch, one agent handles all files.
- **11–30 files**: batch by category (one batch per category: math libraries, oracles, core logic, peripheral). Spawn agents in category order.
- **> 30 files**: same category-based batching, but split any category with more than 10 files into sub-batches of ~8 files each.

Within each batch, the agent processes files sequentially in the order listed.

## Annotation Order

Spawn batches in the recommended discovery order from Phase 1: math libraries first, then oracles, then core logic, then peripheral. Earlier batches establish vocabulary context that later batches depend on — wait for each batch to complete before spawning the next category. Batches within the same category can run in parallel.

## Coverage Gate (Mandatory)

Before launching agents, initialize a Phase 2 status map from `DIMENSIONAL_SCOPE.json`:

- `phase2 = "PENDING"` for every in-scope file.

After each annotator batch completes, update each assigned file to exactly one of:

- `ANNOTATED` — one or more anchor annotations were added or existing anchors were confirmed
- `REVIEWED_NO_ANCHOR_CHANGES` — file reviewed and no anchor edits were needed
- `BLOCKED` — file could not be processed, with reason

Retry `BLOCKED` files once (with focused prompts). If a file remains `BLOCKED` after one retry, keep it as `BLOCKED` with a documented reason and proceed — include it in `coverage.unprocessed_files` in the final output. Do not proceed to Phase 3 while any file remains `PENDING`.

## What to Provide to Each Annotator Agent

Each `dimensional-analysis:dimension-annotator` spawn must include the following in its prompt:

1. **Path to `DIMENSIONAL_UNITS.md`** — the absolute path so the agent can read the vocabulary (base units, derived units, precision prefixes) itself.
2. **Path to `DIMENSIONAL_SCOPE.json`** — so the agent can cross-check scope metadata for assigned files.
3. **Assigned file paths** — the absolute file paths for this batch, in order.
4. **File categories and matched patterns** — from the scanner output (Phase 1), include each file's category (e.g., math library, oracle wrapper, core logic) and the specific patterns that were matched (e.g., precision constants, scaling operations, oracle calls). This gives the agent context on what kind of dimensional arithmetic to expect.
5. **Previously annotated interfaces** — if earlier batches defined key interfaces or types (e.g., a math library's precision constants, an oracle's return types), summarize those annotations so the agent can propagate dimensions through call boundaries.
6. **Required per-file status output** — each file must end with `ANNOTATED`, `REVIEWED_NO_ANCHOR_CHANGES`, or `BLOCKED` (with reason) and a one-line justification.

## Reference Examples

For detailed annotation examples with ERC-4626, AMM, and Lending protocols, see [references/annotate.md](annotate.md).

## Step Completion and Next Workflow File

Only continue when every file in `DIMENSIONAL_SCOPE.json.in_scope_files` has a non-pending Phase 2 status.

Read [references/step3.md](step3.md) next.
