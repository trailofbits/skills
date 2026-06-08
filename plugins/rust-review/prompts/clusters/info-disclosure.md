---
name: cluster-info-disclosure
kind: cluster
consolidated: false
covers:
  - pointer-exposure # PTREXPOSE
---

# Cluster: Information disclosure

Externally observable leaks of internal runtime state the compiler cannot catch: raw memory addresses reaching logs, API responses, serialized output, or error strings, defeating ASLR.

ID prefixes: `PTREXPOSE`.

## Phase A

```
Grep: pattern="\bas\s+usize\b|\{:p\}|\.addr\(\)"
```

Run finders in declared order.
