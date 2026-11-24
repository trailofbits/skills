---
name: implement-patch
description: Use when a confirmed local bug needs an invariant-level fix, variant search, tests, and one local commit.
---

# Implement Patch

## When to Use

Use after independent validation confirms one claim. Read the
[record contract](../../references/records.md).
Before target commands, follow its [project guidance](../../references/records.md#project-guidance).

## When NOT to Use

Do not use for speculative bug hunting, proof of a completed patch, or a change that
cannot be exercised by the local compiler or runtime.

## Procedure

1. Before editing, run `uv run --no-project <script> check --before-repair <run-dir>`
   with the [record validator](../../scripts/records.py). If this check fails,
   stop and return its errors for an INCONCLUSIVE report. The gate requires
   `finding.repair_scope` with a usable case plan and a consistent attempt count.
   Use the declared scope as the repair brief. Identify the broken
   invariant and search within its boundary for every instance of the
   same violation. Read the threat model only to preserve intended behavior; it is
   not a gate.
2. Run the project's existing suite and record its results. Write a regression test
   that fails on the baseline for the named bug and any fixed variant. Observe the
   failure. Fix the invariant within the repair brief with the smallest reviewable change.
3. Run the regression test and full existing suite again. Compare before and after
   failures. Fix new failures or explain a pre-existing one from receipts.
4. Record every variant as `fixed` or `not_fixed` with a reason. Produce exactly one
   local commit. Never push or open a PR. From the baseline, write `fix.patch` for
   production changes and `tests.patch` for test changes in `patch/attempt-N/`.
5. Write `patch.json` with the two commit SHAs, changed-file and line counts,
   variants, suite results, and your agent identity. If the attempt produced no commit,
   record `patch_commit: null` and return it as failed. Manifest the entire attempt
   directory, including both patch files and the record, using
   `uv run --no-project <script> manifest <patch-attempt-dir>`. Check it with the
   [record validator](../../scripts/records.py).

   [Patch record schema](../../schemas/patch.schema.json):
```json
{
  "schema_version": 1,
  "attempt": 1,
  "baseline_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "patch_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "files_changed": 2,
  "lines_added": 3,
  "lines_removed": 1,
  "variants": [],
  "suite_before": {"command": "pytest", "passed": 9, "failed": 1, "skipped": 0},
  "suite_after": {"command": "pytest", "passed": 10, "failed": 0, "skipped": 0},
  "agent": "patcher-1"
}
```

## Rationalizations to Reject

| Shortcut | Required action |
| --- | --- |
| Only the reported line matters. | Search for the same invariant violation. |
| Minimal means the fewest lines. | Make the smallest reviewable invariant-level fix. |
| Tests pass after the patch. | Show the regression test failed before it. |
