---
name: collection-key-mutation-finder
description: Detects mutation of live collection keys in HashMap/HashSet/BTreeMap/BinaryHeap that invalidates Hash/Eq/Ord invariants
---

**Finding ID Prefix:** `KEYMUT`.

**Bug shape:** A key already stored in a `HashMap`/`HashSet`/`BTreeMap`/`BTreeSet`/`BinaryHeap` is mutated so its `Hash`, `Eq`, or `Ord` value changes — via interior mutability inside the key (`Cell`/`RefCell`/`Mutex`/atomics) or `&mut` access to a **stored key** whose mutating guard is then leaked (`BinaryHeap::peek_mut` re-sifts the element on drop, so an ordinary `peek_mut` mutation is **safe** — heap corruption requires `mem::forget`-ing the `PeekMut` guard to skip that re-sift). Subsequent lookups miss the entry, entries leak forever, or heap/tree ordering invariants break, per std docs.

**Gates:**

1. A key type contains interior mutability over fields that affect `Hash`/`Eq`/`Ord`, or code mutates a **stored key** through a `BinaryHeap::peek_mut` guard that is then leaked via `mem::forget`/`ManuallyDrop` (the guard's `Drop` re-sifts, so a normally-dropped `peek_mut` is safe — do not flag it). (Note: `HashMap`/`BTreeMap::get_mut` return `&mut V` — the **value**, never the key — and `HashSet` has no `get_mut`, so neither is a key-mutation path.)
2. A field affecting `Hash`/`Eq`/`Ord` is changed while the value remains in the collection.

**FPs:**

- `BinaryHeap::peek_mut` whose `PeekMut` guard is dropped normally (not `mem::forget`-ed) — its `Drop` re-sifts the mutated element, preserving the heap invariant.
- The mutated field is explicitly excluded from the `Hash`/`Eq`/`Ord` impls.
- The key is removed from the collection, mutated, then reinserted.
- Keys are effectively immutable (no interior mutability, no `&mut` access path exists).

**Patch:** Keep keys immutable; remove, mutate, then reinsert; or explicitly exclude mutable state from the key's `Hash`/`Eq`/`Ord` impls.
