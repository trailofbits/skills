# Ranking

Rank candidates by review value, not by confirmed severity.

## Positive Signals

| Signal | Effect |
|---|---|
| Entrypoint-reachable | Strong priority increase |
| Untrusted or semi-trusted entrypoint path | Strong priority increase |
| Tainted | Strong priority increase |
| Privilege-boundary adjacent | Strong priority increase |
| High blast radius | Priority increase |
| Shares vulnerable sink | Priority increase |
| Same interface, override, trait, hook, or adapter family | Priority increase |
| Same critical type or state reference | Priority increase |
| Graph distance 1 or 2 from seed | Priority increase |

## Negative Signals

| Signal | Effect |
|---|---|
| Unreachable from modeled entrypoints | Lower priority; keep if root cause is strong |
| Trusted-internal-only | Lower priority |
| Test, mock, generated, or vendor code | Exclude unless in scope |
| Ambiguous binding | Lower confidence |
| Proxy or dynamic edge uncertainty dominates | Lower confidence and add limitation |

## Rank Labels

| Rank | Meaning |
|---|---|
| `High` | Review first; strong structural similarity and reachability |
| `Medium` | Plausible variant; needs semantic review |
| `Low` | Weak or unreachable candidate; keep for completeness or deferred review |
| `Excluded` | Out of scope, generated, vendor, or insufficient binding |

## Confidence Labels

| Confidence | Use when |
|---|---|
| `High` | Exact binding, explicit relationship, clear reachability |
| `Medium` | Clear relationship but some path or root-cause uncertainty |
| `Low` | Ambiguous binding, dynamic dispatch uncertainty, or weak similarity |
