---
name: lossy-from-into-finder
description: Detects From/Into and `as` casts that silently truncate or lose information across security boundaries
---

**Finding ID Prefix:** `LOSSYFROM`.

**Gates:**

1. `impl From<A> for B` (or `as` cast) where `B` cannot represent all `A` values (narrower integer, signed-to-unsigned, float-to-int).
2. The conversion site is on a security-relevant path: length field, capability check, authorization token, ID lookup.

**FPs:**

- Conversion is bounded by a prior explicit `< MAX` check.
- Using `TryFrom`/`try_into()` already.

**Patch:** prefer `TryFrom` + `?`.
