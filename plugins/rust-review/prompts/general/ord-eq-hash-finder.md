---
name: ord-eq-hash-finder
description: Detects manual Ord/PartialOrd/Eq/PartialEq/Hash impls that violate required invariants
---

**Finding ID Prefix:** `ORDEQHASH`.

**Gates:**

1. Manual (non-derived) `impl Ord` / `impl PartialOrd` / `impl Eq` / `impl PartialEq` / `impl Hash` exists.
2. At least one invariant is checkable as violated by reading the impl: (a) `a == b ⟹ hash(a) == hash(b)`, (b) `Ord::cmp` total order consistency with `PartialOrd::partial_cmp`, (c) `Eq` reflexivity/symmetry/transitivity, (d) NaN handling for floats.

**Why:** violations corrupt `HashMap`/`BTreeMap` (collisions, missing keys, infinite loops in some std internals).

**Patch:** derive when possible; otherwise document invariant proofs and add property tests.
