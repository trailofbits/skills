---
name: cluster-input-os-safety
kind: cluster
consolidated: false
covers:
  - path-traversal-join # PATHJOIN
  - toctou              # TOCTOU
---

# Cluster: Input & OS-interaction safety

Safe-code bugs at the boundary with untrusted input and the OS that the compiler cannot catch: path handling, filesystem races.

ID prefixes: `PATHJOIN`, `TOCTOU`.

## Phase A

```
Grep: pattern="\.join\(|\.push\(|PathBuf"
Grep: pattern="\.exists\(\)|\.metadata\(|symlink_metadata"
Grep: pattern="File::(open|create)"
```

Run finders in declared order.
