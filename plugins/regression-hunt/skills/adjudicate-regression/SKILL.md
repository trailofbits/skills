---
name: adjudicate-regression
description: Use when deciding whether source and live reproduction evidence establish a new regression or an exclusion.
---

# Adjudicate evidence

## When to Use

Input: candidate, frozen sources, available reproduction/replay packages and
registry assignment. Use a fresh context distinct from the reproducer
and replayer. Early exclusions may lack experiments.
Follow [project guidance](../../references/evidence.md#project-guidance) before target work.

## When NOT to Use

Producing missing evidence; return the gap to the caller.

## Decide

1. Read the [standard](../../docs/regression-definition.md),
   [labels](../../docs/report-definitions.md) and
   [file contract](../../references/evidence.md). Verify seals. Inspect source,
   setup, PoC, actual logs and security assumptions, not only summaries.
2. Identify the claimed defect and assess whether the change introduced it. Rule out
   incomplete fixes, latent/pre-existing bugs, intentional changes, unsupported expectations
   and unreachable scenarios with cited evidence. Establish attacker access and applicable protections for
   security findings.
3. Confirm only when reproduction and independent replay ran the same PoC/input
   against live S0/S1 through real interfaces, showing correct behavior before and
   failure afterward. Explain supported behavior, reachability and patch causality.
   Assign severity/likelihood with reasons.
4. Otherwise select an evidenced exclusion or `UNRESOLVED`; state what remains
   unproved. For `UNRESOLVED`, put the standard's concise paragraph separating observed gaps,
   plausible explanations and resolving checks in `reason` so reports retain it.
   Incomplete fixes and existing bugs stay outside regression totals.
   Check known findings/issues/PRs before claiming novelty; report unknown if unavailable.
5. For requested deduplication, establish whether supplied candidates share a root
   cause. Preserve change mappings; never deduplicate unresolved claims into confirmation.
6. Write and seal `decision.json`; cite evidence for every conclusion.
   Record any blocker preventing adjudication.

## Report Back

Keep detailed reasoning in the sealed package. Return only:

- Status: `complete` or `blocked`, matching the record.
- Record: sealed `decision.json` path, or why none was produced.
- Result: outcome and one-sentence reason.
- Gap: missing evidence or required caller action, if any.

A completed decision may be `UNRESOLVED`; task status and finding outcome differ.

## Rationalizations to Reject

- “S0 passes and S1 fails”: exposing an existing defect is a latent bug.
