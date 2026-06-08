---
name: cluster-logic-correctness
kind: cluster
consolidated: false
covers:
  - ord-eq-hash                # ORDEQHASH
  - adversarial-trait          # TRAITADV
  - closure-panic              # CLOSUREPANIC
  - float-edge                 # FLOATEDGE
  - string-comparison          # STRCMP
  - serialize-struct-mismatch  # SERFIELDS
  - nondeterminism             # NONDET
  - collection-key-mutation    # KEYMUT
---

# Cluster: Logic correctness

ID prefixes: `ORDEQHASH`, `TRAITADV`, `CLOSUREPANIC`, `FLOATEDGE`, `STRCMP`, `SERFIELDS`, `NONDET`, `KEYMUT`.

## Phase A

```
Grep: pattern="impl\s+(Ord|PartialOrd|Eq|PartialEq|Hash)\s+for"
Grep: pattern="\b(f32|f64)\b"
Grep: pattern="<\s*\w+\s*:\s*[A-Z]"  # generic trait bounds
Grep: pattern="\bcatch_unwind\b"
Grep: pattern="\b(starts_with|ends_with|contains)\b"
Grep: pattern="serialize_struct\("
Grep: pattern="\bHashMap\b|\bHashSet\b"
Grep: pattern="peek_mut|RefCell\b|Cell\b"
```

Run finders in declared order.
