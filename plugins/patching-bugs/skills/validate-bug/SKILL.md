---
name: validate-bug
description: Use when a bug PoC package needs an independent rerun and judgment before patching.
---

# Validate Bug

## When to Use

Use after `reproduce-bug` has supplied a finding and PoC package. Read the
[record contract](../../references/records.md).
Before target commands, follow its [project guidance](../../references/records.md#project-guidance).

## When NOT to Use

Do not use to repair a PoC, develop a patch, or infer reproduction from the
reproducer's narrative.

## Procedure

1. Read `finding.json`, the reproduction's proof type, commands, any PoC, and raw receipts.
   Do not read the reproducer's transcript.
2. Rerun the same baseline compiler command for compile failures, or rebuild and rerun
   the unchanged runtime PoC and planned scoped inputs. Save stdout, stderr, exit
   status and timing in `validate/receipts/`. If an observation is unreliable,
   return `inconclusive` instead of inferring either presence or absence.
3. Decide whether the target diagnostic or runtime assertion demonstrates the exact claim and
   violates the stated invariant. Write `validate.json` as `confirmed`,
   `not_confirmed`, or `inconclusive` with a short reason and agent identity.

   [Validate record schema](../../schemas/validate.schema.json):
```json
{
  "schema_version": 1,
  "outcome": "confirmed",
  "agent": "validator-1",
  "reason": "The unchanged PoC reached the assertion and demonstrated the claim."
}
```

4. Manifest the complete `validate/` directory with
   `uv run --no-project <script> manifest <validate-step-dir>`, then run the
   [record checker](../../scripts/records.py). Return
   the package without editing the PoC or finding.

## Rationalizations to Reject

| Shortcut | Required action |
| --- | --- |
| Fix the PoC to make the claim work. | Mark it inconclusive and explain why. |
| Trust the reproducer's conclusion. | Rerun the unchanged package independently. |
