---
name: buffer-overflow-unsafe-finder
description: Detects safe-side index arithmetic flowing into unchecked unsafe memory access
---

**Finding ID Prefix:** `BOF`.

**Bug shape (from research):** 17/21 production Rust buffer overflows fit this shape — safe code computes an offset/size/index, then passes it into `get_unchecked(_mut)`, `copy_nonoverlapping`, `ptr::write`, or a raw-pointer `.offset()`/`.add()`/`.sub()` method call. The unsafe block trusts the safe boundary; the safe arithmetic is wrong. (`offset`/`add`/`sub` are **methods** on raw pointers, not `ptr::` free functions.)

**Verification gates:**

1. **Unchecked sink:** the unsafe block contains one of `get_unchecked(_mut)`, `copy_nonoverlapping`, `ptr::write`, or a raw-pointer `.offset()`/`.add()`/`.sub()` method call.
2. **Index from safe code:** the offset / index / size parameter is computed in safe Rust.
3. **No sound bounds proof:** the safe arithmetic does NOT prove `index < len()` of the slice/Vec the unsafe op indexes — the `get_unchecked` family's safety contract is `index < len`, **not** capacity (indices in `len..capacity` are uninitialized and reading them is UB; `&[T]` has no `capacity()` at all). Account for `usize` overflow, `as` truncation, and signed/unsigned mixing in that proof.
4. **Attacker reachability:** the safe input flows from a `pub fn` or trait-impl method invokable by an attacker (file the URAPI in cross-cluster references but the finding location is the unsafe block).

**FPs:**

- Index is a hardcoded constant statically less than the indexed slice/array's **length** (for a fixed-size `[T; N]`, `len == N`, so a constant `< N` is safe). A constant that is `< capacity` but `>= len` is **not** an FP — `len..capacity` is uninitialized (see gate 3 and the `.capacity()` note below).
- Bounds check uses `checked_*` / `saturating_*` arithmetic AND is compared against `.len()` of the same slice/Vec the unsafe op indexes. (A guard against `.capacity()` is **not** an FP — it admits uninitialized `len..capacity` indices, so REPORT it.)
- Caller is private (`fn`, not `pub fn`, no exposed trait impl) and all internal callsites pass safe constants.

**Search patterns:**

```
\bget_unchecked(_mut)?\s*\(
copy_nonoverlapping\s*\(
ptr::write\s*\(|\.(offset|add|sub)\s*\(
\bas\s+(usize|u32|u16|u8|i32|isize)
```

**Patch:** replace `get_unchecked(i)` with `.get(i)` (returns `Option`), or validate `i < <indexed slice>.len()` with `checked_*` arithmetic before the unsafe block. `capacity` is the wrong bound for the `get_unchecked` family — only the spare-capacity write pattern (`len..capacity` before `set_len`) involves capacity, and only once those slots are initialized.
