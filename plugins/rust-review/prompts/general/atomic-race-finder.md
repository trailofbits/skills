---
name: atomic-race-finder
description: Detects non-atomic read-modify-write sequences on Atomic* types
---

**Finding ID Prefix:** `ATOMICRACE`.

**Bug shape:** `let v = a.load(Ordering::Acquire); if v == X { a.store(Y, Ordering::Release); }` — two independent ops; another thread can race between them.

**Gates:**

1. `Atomic*.load(...)` followed by conditional `Atomic*.store(...)` on the same variable, where the store is dependent on the load.
2. No `compare_exchange` / `compare_exchange_weak` / `fetch_update` in between.
3. The Atomic is shared (`Arc<Atomic*>`, `static`, or field of `Arc<...>`).

**Patch:** convert to `compare_exchange` loop or `fetch_update`.

**Search patterns:**

```
\.load\s*\(
\.store\s*\(
\.compare_(exchange|and_swap)
```
