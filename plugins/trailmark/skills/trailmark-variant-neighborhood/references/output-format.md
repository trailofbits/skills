# Output Format

Use Markdown unless the user asks for JSON.

```markdown
# Trailmark Variant Neighborhood

## Seed

- Finding:
- Bound node:
- Root cause:

## Candidate Summary

| Rank | Candidate | Reason | Reachability | Confidence |
|---|---|---|---|---|

## Graph Neighborhoods

### Shared Callers
### Shared Callees / Sinks
### Entrypoint Path Neighbors
### Interface Or Implementation Siblings
### Type / State Neighbors

## Variant-Analysis Handoff

- Root cause:
- Keep specific:
- Abstract:
- Suggested searches:
- Suggested CodeQL/Semgrep direction:

## Exclusions And Limitations
```

## Wording Requirements

- Say "candidate" or "review target", not "variant vulnerability".
- Explain why each candidate was included.
- Separate graph similarity from semantic root-cause similarity.
- Include exclusions so reviewers understand why obvious nearby code was not
  prioritized.

## Handoff Guidance

For `variant-analysis`, provide:

- seed location
- root cause in one sentence
- ranked candidate table
- positive and negative examples
- graph dimensions that produced useful candidates

For `semgrep-rule-creator`, provide:

- the syntax that should stay specific
- the syntax that should be abstracted
- at least one true-positive candidate and one likely negative example

For `static-analysis`, provide:

- candidate files and functions
- suggested source, sink, or path query shape
- SARIF output expectation if the user wants machine-readable results
