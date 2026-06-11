# Output Format

Use Markdown unless the user asks for JSON.

```markdown
# Trailmark Review Gate

## Verdict

Gate: PASS | WARN | FAIL | UNKNOWN
Confidence: High | Medium | Low

## Triggered Rules

| Rule | Verdict | Evidence |
|---|---|---|

## Structural Changes

| Change | Before | After | Review target |
|---|---|---|---|

## Entrypoint And Reachability Changes

## Privilege And Taint Changes

## Blast Radius And Complexity Changes

## Limitations

## Recommended Reviewer Actions
```

## Evidence Requirements

For each triggered rule, include:

- changed node or edge identifier
- source file or symbol when available
- entrypoint path when relevant
- before/after metric when metric-based
- manual review target

## Wording Requirements

- Say "gate fired" instead of "vulnerability found".
- Say "review target" instead of "exploit path" unless exploitability is
  separately established.
- Say `UNKNOWN` when Trailmark fails or parser support is too incomplete.
- Do not claim a `PASS` means the change is secure.
