# Vector Forge Report Template

Write the report to `VECTOR_FORGE_REPORT.md` in the working directory.

```markdown
# Vector Forge Report

## Target Algorithm
[Algorithm name and specification reference]

## Implementations Tested

| Library | Language | Type | Mutation Framework |
|---------|----------|------|--------------------|

## Baseline Results (Existing Vectors Only)

[Per-implementation baseline table]

## Escape Analysis

### [Implementation Name]
- Total escaped: N
- By code path:
  - [Path 1]: N mutants — [description]
  - [Path 2]: N mutants — [description]

## New Vectors Generated

| Vector ID | Target Code Path | Expected Kill |
|-----------|-----------------|---------------|

## After Results (With New Vectors)

[Per-implementation after table]

## Before/After Comparison

[Delta table per implementation]

## Conclusions
[What the vectors caught, what they missed, and why]
```
