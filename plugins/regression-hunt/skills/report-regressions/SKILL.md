---
name: report-regressions
description: Use when assembling or refreshing an evidence-linked regression report from saved campaign decisions.
---

# Report a campaign

## When to Use

Input: frozen `scope.json`, campaign index, progress ledger, sealed stage packages
and registry assignment.
Follow [project guidance](../../references/evidence.md#project-guidance) for every scoped change before reporting.

## When NOT to Use

Adjudicating evidence or repairing records; return those needs to the caller.

## Report

1. Read the [standard](../../docs/regression-definition.md),
   [labels](../../docs/report-definitions.md) and
   [file contract](../../references/evidence.md). Reconcile the index against
   frozen scope, assigned changes and discovered candidates. Preserve PR/commit IDs and
   accepted duplicate mappings.
2. Run [report.py](../../scripts/report.py) via `uv run --no-project` with the campaign
   directory and `--output ASSIGNED_DIRECTORY/reports` to render HTML, Markdown and JSON.
   Exit 1 means changed evidence or an invalid index; return its diagnostics and record the stage as blocked. Exit 0 may include `UNRESOLVED` findings; report each `unresolved_reason` and the `verification` level of confirmed findings. Never repair decisions, invent
   evidence or edit hashes to pass validation.
3. Inspect counts and links. Preserve adjudicated outcomes/ratings. Separate
   incomplete fixes, latent/pre-existing bugs, rejected claims and unresolved
   work from confirmed totals.
4. Ensure reports include coverage gaps, setup/execution evidence, rating reasons
   and pending human review. Report missing information; do not claim completion
   while required content is absent.
   Seal `report-stage.json` with the assigned inputs and generated reports as artifacts;
   record validation failures as blocked.

## Report Back

Keep detailed findings in the reports. Return only:

- Status: `complete` or `blocked` for report production.
- Reports: sealed `report-stage.json` and validated output paths; identify incomplete outputs.
- Result: one sentence describing campaign coverage and unresolved work.
- Blocker: affected records, validation errors or required caller action.

A complete report may describe an incomplete campaign.

## Rationalizations to Reject

- “All agents finished”: that does not establish coverage or resolved candidates.
