---
name: cluster-logic-correctness
kind: cluster
consolidated: false
covers:
  - ord-eq-hash       # ORDEQHASH
  - adversarial-trait # TRAITADV
  - closure-panic     # CLOSUREPANIC
  - float-edge        # FLOATEDGE
---

# Cluster: Logic correctness

ID prefixes: `ORDEQHASH`, `TRAITADV`, `CLOSUREPANIC`, `FLOATEDGE`.

## Phase A

```
Grep: pattern="impl\s+(Ord|PartialOrd|Eq|PartialEq|Hash)\s+for"
Grep: pattern="\b(f32|f64)\b"
Grep: pattern="<\s*\w+\s*:\s*[A-Z]"  # generic trait bounds
Grep: pattern="\bcatch_unwind\b"
```

Run finders in declared order.
