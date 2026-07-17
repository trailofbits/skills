---
name: vec-set-len-uninit-finder
description: Detects Vec length advanced without initializing new elements, exposing uninitialized memory through safe Rust APIs
---

**Finding ID Prefix:** `SETLEN`.

**Bug shape:** `Vec::set_len`, `spare_capacity_mut` followed by `set_len`, or `Vec::from_raw_parts` commits a `len` that counts slots not yet initialized. The vector's *safe* API (`&vec[..]`, `vec[i]`, `Drop` of elements, `Read::read(&mut vec[..])`, returning the `Vec` to callers) then treats uninitialized memory as valid `T`. For non–all-bit-pattern types this is immediate UB; even for `u8` it is unsound, since `Read` into an uninit `&mut [u8]` is documented UB.

**Verification gates (ALL must pass):**

1. **Length advanced:** `unsafe { vec.set_len(new_len) }`, `Vec::from_raw_parts(ptr, len, cap)`, or a `set_len` after `spare_capacity_mut()` / `with_capacity` / `reserve` growth, with `new_len > old_len`.
2. **Init gap:** at least one index in `old_len..new_len` has no dominating initialization on all paths before the length is committed — no `ptr::write` / `write_bytes`, no assignment through an initialized `&mut T` slot, no `copy_nonoverlapping` from a fully initialized source, no per-element `MaybeUninit::write`.
3. **Safe exposure:** after the length change, uninitialized slots are reachable via safe code (slice deref, indexing, iteration, `Drop` on `Vec<T>` where `T: Drop`, `std::io::Read`/`Write`, or a `pub` return of the `Vec`).

**FPs to reject:**

- `new_len <= old_len` (truncate-only `set_len`, or empty range — no new slots claimed).
- Every slot in `old_len..new_len` is written before `set_len` (trace `spare_capacity_mut` → `.write(...)` / `copy_from_slice` / `fill`), or the buffer came from `vec![val; n]` / `resize` / `extend` so capacity is already initialized.
- `Vec<MaybeUninit<T>>` whose elements are never treated as `T` until per-slot init (verify no `transmute` to `Vec<T>`).
- `from_raw_parts` where `ptr`/`len` transfer from a fully initialized `Box<[T]>` / `Vec` with matching provenance.

**Search patterns:**

```
\bset_len\s*\(
\bfrom_raw_parts\s*\(
\bspare_capacity_mut\s*\(
```

**Patch:** initialize via `spare_capacity_mut()` → per-slot `MaybeUninit::write`, then `unsafe { set_len }`; or use `vec![0; n]` / `resize` into an already-initialized buffer; or keep `Vec<MaybeUninit<T>>` until conversion is sound.

Distinct from `UNINITREAD` (`MaybeUninit::assume_init` without field writes) and `BOF` (in-bounds *initialized* memory accessed past capacity via unchecked pointer ops).
