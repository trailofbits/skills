---
name: hunt-regressions
description: Use when discovering possible regressions from a pinned change and its callers before reproduction.
---

# Discover candidates

## When to Use

Input: sealed preparation, frozen S0/S1, change context and registry assignment.
On retry, include this assignment's prior candidate-ID mapping. The caller supplies
these, including for independent use.
Follow [project guidance](../../references/evidence.md#project-guidance) before target work.

## When NOT to Use

Proving a known candidate; use reproduction. Discovery cannot confirm findings.

## Hunt

1. Read the [standard](../../docs/regression-definition.md) and
   [file contract](../../references/evidence.md). Verify preparation; read frozen
   change messages, PR discussion and security documentation for intent and supported use.
2. Review the entire diff; trace changed behavior through callers to real interfaces.
   Use frozen sources and supplied context, not later fixes, advisories or other reviews.
3. Record each lead's changed code, previously supported behavior, reachable trigger,
   proposed new defect, false-positive checks and required proof. Retain supplied
   leads suggesting old bugs or incomplete fixes for adjudication.
   Leave PoC construction to reproduction.
4. Reserve each lead's ID through [registry.py](../../scripts/registry.py) `candidate`
   using its stable hypothesis key and assigned agent handle. Reuse the key on retry.
   Write candidate files and `hunt.json` with IDs, file mappings, coverage and limitations.
   An empty list is valid.
   If blocked, record partial coverage and uninspected areas. Seal the package.

## Report Back

Keep detailed evidence in the sealed package. Return only:

- Status: `complete` or `blocked`, matching the record.
- Record: sealed `hunt.json` path, or why none was produced.
- Result: candidate count and material coverage gaps.
- Blocker: missing prerequisite or required caller action, if blocked.

## Rationalizations to Reject

- “A helper fails on invented input”: show a supported interface that reaches it.
