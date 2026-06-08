---
name: collection-key-mutation-finder
description: Detects mutation of live collection keys in HashMap/HashSet/BTreeMap/BinaryHeap that invalidates Hash/Eq/Ord invariants
---

**Finding ID Prefix:** `KEYMUT`.

**Bug shape:** A key already stored in a `HashMap`/`HashSet`/`BTreeMap`/`BTreeSet`/`BinaryHeap` is mutated so its `Hash`, `Eq`, or `Ord` value changes — via interior mutability inside the key (`Cell`/`RefCell`/`Mutex`/atomics) or `&mut` access (e.g. `BinaryHeap::peek_mut`, retained `get_mut` references). Subsequent lookups miss the entry, entries leak forever, or heap/tree ordering invariants break, per std docs.

**Gates:**

1. A key type contains interior mutability over fields that affect `Hash`/`Eq`/`Ord`, or code obtains mutable access to a live key (`peek_mut`, `get_mut`).
2. A field affecting `Hash`/`Eq`/`Ord` is changed while the value remains in the collection.

**FPs:**

- The mutated field is explicitly excluded from the `Hash`/`Eq`/`Ord` impls.
- The key is removed from the collection, mutated, then reinserted.
- Keys are effectively immutable (no interior mutability, no `&mut` access path exists).

**Patch:** Keep keys immutable; remove, mutate, then reinsert; or explicitly exclude mutable state from the key's `Hash`/`Eq`/`Ord` impls.
