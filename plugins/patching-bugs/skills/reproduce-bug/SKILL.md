---
name: reproduce-bug
description: Use when a named runtime or compiler bug in a local repository needs independent reproduction.
---

# Reproduce Bug

## When to Use

Use for the reproduction step of `patching-bugs` with one `finding.json` and a local
baseline checkout. Read the [record contract](../../references/records.md).
Before target commands, follow its [project guidance](../../references/records.md#project-guidance).

## When NOT to Use

Do not use for bug discovery, patching, or a claim that cannot be exercised locally.
Report a blocker when the build or environment cannot exercise the claim.

## Procedure

1. Select `failure_type` from the record contract. Build the current baseline with the
   project's own command. Exercise the planned scoped inputs before any edit and
   retain their observations, including valid controls. Save raw stdout, stderr,
   exit status, and timing. If the behavior is absent with trustworthy evidence,
   report `not_reproduced`; if setup or observations are unreliable, report `blocked`.
2. Runtime: exercise the built `target_artifact` with a PoC that records `PATCH_LOADED`
   as defined in the contract, then prints `PATCH_REACHED` immediately before the assertion.
   Exit nonzero for the bug, zero otherwise; a setup crash is inconclusive.
   Compile: record the target `expected_diagnostic` from the failed compiler invocation;
   use empty `poc_argv` and null `target_artifact`.
3. Save any unchanged PoC source under `reproduce/poc/` and raw receipts
   under `reproduce/receipts/`. Write `reproduce.json` with the baseline commit,
   command argument arrays, artifact path, observed result, outcome, and your agent
   identity. Set `finding.status` to `reproduced` or `not_reproduced` from the result.
   If reproduction is `blocked`, leave `finding.status` as `hypothesis`.

   [Reproduce record schema](../../schemas/reproduce.schema.json):
```json
{
  "schema_version": 1,
  "failure_type": "runtime",
  "outcome": "reproduced",
  "baseline_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "build_argv": ["python", "build.py"],
  "poc_argv": ["python", "poc.py"],
  "target_artifact": "dist/app.py",
  "observed": "The PoC wrote outside uploads after PATCH_REACHED.",
  "blocker": null,
  "agent": "reproducer-1"
}
```

4. Manifest the complete `reproduce/` directory, including the PoC and record, using
   the [record helper](../../scripts/records.py): run
   `uv run --no-project <script> manifest <reproduce-step-dir>`. Then check the
   record before handoff. State `blocked` with the actual failure when build or setup
   prevents a valid run.

## Rationalizations to Reject

| Shortcut | Required action |
| --- | --- |
| A unit test imitates the bug. | Exercise the target compiler or built runtime artifact. |
| A nonzero exit proves reproduction. | Require the target diagnostic, or runtime marker and assertion. |
