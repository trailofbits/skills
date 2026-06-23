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
rg seed: "\.join\(|\.push\(|PathBuf"
rg seed: "\.exists\(\)|\.metadata\(|symlink_metadata"
rg seed: "File::(open|create)"
```

Run finders in declared order.

## Deconfliction

- `PATHJOIN` vs `TOCTOU`: an attacker-controlled path component that escapes the intended directory (an absolute component replacing the base, `..` traversal) is `PATHJOIN`. A race between a filesystem check (`exists` / `metadata` / `symlink_metadata`) and a later use of the *same* path is `TOCTOU`. When a single sink (e.g. `File::open(base.join(user_input))` after an `exists()` check) matches both greps, file `PATHJOIN` for the directory escape and `TOCTOU` only when a distinct check→use window is independently exploitable.
