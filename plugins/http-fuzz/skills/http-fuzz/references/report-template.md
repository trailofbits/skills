# Fuzz Report Template

Write `./http-fuzz-report.md` using this structure:

```markdown
# HTTP Fuzz Report

- **Target**: <METHOD> <URL>
- **Date**: <date>
- **Aggression**: <level> (<N> threads, <MS>ms delay)
- **Parameters fuzzed**: <list> (<N> of <total>; <excluded> excluded)

## Summary

- Requests sent: <N>
- Anomalies found: <N>
- Connection failures: <N>
- Baseline: <status> OK, median <N>ms

## Anomalies

| # | Parameter | Value | Status | Time (ms) | Finding |
|---|-----------|-------|--------|-----------|---------|
| 1 | email | `a@b.c'--` | 500 | 89 | SQL syntax in response body |

### Anomaly 1: <Short Title>

**Parameter**: `email`
**Value**: `a@b.c'--`
**Response**: 500 Internal Server Error
**Body preview**: `...SQL syntax error near '--'...`

<One sentence explaining what the anomaly indicates.>

[... one section per anomaly ...]

## Corpus Files

Reusable corpus files were written to `./corpus/`:
- `./corpus/email.txt` (<N> values)
- `./corpus/role.txt` (<N> values)

## Raw Evidence Appendix

<details>
<summary>Baseline responses</summary>

[full baseline JSON]

</details>

<details>
<summary>Full anomalous responses</summary>

[full response bodies for each anomaly]

</details>
```

## Writing Guidelines

- One sentence per anomaly explaining the observable effect — be specific about the mechanism
  (`SQL syntax error` not `server error`), note what it *suggests* not what it *proves*
- Reference both the input value and the observable effect in each anomaly description
- If no anomalies were found, say so explicitly — a clean result is a valid result
- Connection failures go in the summary count, not the anomaly table
