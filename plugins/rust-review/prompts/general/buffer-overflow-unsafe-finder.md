---
name: buffer-overflow-unsafe-finder
description: Detects safe-side index arithmetic flowing into unchecked unsafe memory access
---

**Finding ID Prefix:** `BOF`.

**Bug shape (from research):** 17/21 production Rust buffer overflows fit this shape — safe code computes an offset/size/index, then passes it into `get_unchecked(_mut)`, `copy_nonoverlapping`, `ptr::offset`, `ptr::add`, or `ptr::write`. The unsafe block trusts the safe boundary; the safe arithmetic is wrong.

**Verification gates:**

1. **Unchecked sink:** the unsafe block contains one of `get_unchecked(_mut)`, `copy_nonoverlapping`, `ptr::write`, `ptr::offset`, `ptr::add`.
2. **Index from safe code:** the offset / index / size parameter is computed in safe Rust.
3. **No sound bounds proof:** the safe arithmetic does NOT prove `index < capacity` (not just `< len`), accounting for `usize` overflow, `as` truncation, and signed/unsigned mixing.
4. **Attacker reachability:** the safe input flows from a `pub fn` or trait-impl method invokable by an attacker (file the URAPI in cross-cluster references but the finding location is the unsafe block).

**FPs:**

- Index is a hardcoded constant statically less than known capacity.
- Bounds check uses `checked_add` / `saturating_sub` AND is compared against `.capacity()`, not `.len()`.
- Caller is private (`fn`, not `pub fn`, no exposed trait impl) and all internal callsites pass safe constants.

**Search patterns:**

```
\bget_unchecked(_mut)?\s*\(
copy_nonoverlapping\s*\(
ptr::(write|offset|add|sub)\s*\(
\bas\s+(usize|u32|u16|u8|i32|isize)
```

**Patch:** replace `get_unchecked(i)` with `.get(i)` (returns `Option`); validate `i < self.capacity()` with `checked_*` arithmetic before the unsafe block.
