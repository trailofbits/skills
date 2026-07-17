# Gate Rules

Start with deterministic, conservative rules. A triggered rule creates a
review obligation; it does not prove a vulnerability.

| Rule | Verdict | Why it matters |
|---|---|---|
| New untrusted entrypoint | `FAIL` | Expands external attack surface |
| New path from untrusted entrypoint to sensitive sink | `FAIL` | Creates a candidate exploit path |
| Removed auth, validation, or sanitization call on reachable path | `FAIL` | Common regression in fixes and feature PRs |
| Newly tainted privilege-boundary node | `FAIL` | Trust transition now handles untrusted data |
| Blast radius growth above threshold | `WARN` | A bug may now affect more code |
| Complexity growth on tainted or boundary node | `WARN` | Risky logic became harder to review |
| New unresolved, proxy, or dynamic call on reachable path | `WARN` | Graph uncertainty increased in a risky area |
| Dead security function removed | `WARN` | May be cleanup or accidental security removal |

## Default Thresholds

Use these defaults unless the repository has stricter local rules:

| Signal | Default threshold |
|---|---|
| Blast radius growth | `+5` downstream reachable nodes or `+25%`, whichever is larger |
| Complexity growth | cyclomatic complexity `+3` on tainted, boundary, or entrypoint-reachable node |
| Sensitive sink path | any new path from untrusted entrypoint to sink |
| Unresolved/proxy growth | any new unresolved/proxy edge on an entrypoint-reachable path |

Thresholds are intentionally conservative. They reduce noise while still
catching structural changes that line diffs often understate.

## Sensitive Sink Categories

Flag new reachable paths to:

- value transfer
- authorization or role decisions
- persistence or state writes
- parsing or deserialization
- cryptographic keys, sessions, or signatures
- external process, network, or file operations
- upgrade, plugin, hook, or dynamic dispatch mechanisms

## Rule Precedence

Use the most severe triggered verdict:

1. `UNKNOWN` if Trailmark cannot produce adequate evidence
2. `FAIL` if any fail rule triggers
3. `WARN` if any warn rule triggers
4. `PASS` only if evidence is adequate and no rule triggers

If both `UNKNOWN` and `FAIL` seem applicable, emit `UNKNOWN` and list the
suspected fail condition as a manual review target.
