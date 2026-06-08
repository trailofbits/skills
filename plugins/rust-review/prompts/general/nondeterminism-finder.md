---
name: nondeterminism-finder
description: Detects HashMap/HashSet iteration or other nondeterministic sources feeding determinism-sensitive consumers
---

**Finding ID Prefix:** `NONDET`.

**Bug shape:** Logic that must be deterministic (consensus, replicated state machines, signatures/hashes over serialized data, reproducible output) iterates over `HashMap`/`HashSet` whose traversal order is randomized per-process. Also covers float bit-representation variance, pointer addresses, and `usize`/`c_char` width differences fed into canonical serialization or hashed output.

**Gates:**

1. Iteration over `HashMap`/`HashSet` (or float serialization, address values, `usize` layout) feeds a hash, signature, canonical serialization, or replicated state decision.
2. The consumer requires identical output across runs or machines.

**FPs:**

- Downstream consumer does not observe order (e.g. set-equality check, accumulation into a commutative operation).
- `BTreeMap`/`BTreeSet` or explicit `.sort()` is already applied before the sensitive use.
- Output is purely local/cosmetic with no cross-machine or cross-run replay requirement.

**Patch:** Iterate `BTreeMap`/`BTreeSet` or sort keys before use; use a canonical fixed-width encoding for floats/integers; never feed pointer addresses into deterministic state.
