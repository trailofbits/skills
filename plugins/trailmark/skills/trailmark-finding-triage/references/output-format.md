# Output Format

Return a concise evidence packet. Use Markdown unless the user asks for JSON.

```markdown
# Trailmark Finding Triage: <title>

## Verdict

Status: Promote | Needs manual review | Deprioritize | Blocked
Confidence: High | Medium | Low

## Candidate

- Source:
- Location:
- Bound node:
- Claimed issue:

## Graph Evidence

- Entrypoint reachable:
- Entry paths:
- Tainted:
- Privilege boundary:
- Blast radius:
- Direct callers:
- Direct callees:
- Relevant sinks:

## Manual Review Targets

| Target | Why it matters |
|---|---|

## Limitations

## Recommended Next Step
```

## Verdict Criteria

| Verdict | Use when |
|---|---|
| `Promote` | The candidate binds cleanly, has reachable entrypoint paths, and graph evidence supports plausible impact |
| `Needs manual review` | The candidate is reachable but exploitability depends on validation, authorization, type, or state semantics |
| `Deprioritize` | The candidate is not entrypoint-reachable, is only trusted-internal, or sits in test/generated/vendor code outside scope |
| `Blocked` | The candidate cannot be bound, Trailmark fails, or the language/parser is unsupported |

## Confidence Criteria

| Confidence | Use when |
|---|---|
| `High` | Binding is exact, paths are explicit, and graph evidence is consistent |
| `Medium` | Binding is clear but path or sink evidence has uncertainty |
| `Low` | Binding is ambiguous, dynamic dispatch/proxy edges dominate, or important graph features are unavailable |

## Wording Requirements

- Say "graph evidence supports" instead of "Trailmark proves".
- Say "manual review target" for validators, auth checks, and sanitizers.
- Separate "reachable" from "attacker controlled".
- Separate "candidate" from "confirmed vulnerability".
