---
name: opaque-pointer-finder
description: Detects use-after-invalidate or double-free of an opaque FFI handle (handle used or freed again after the C side already freed/destroyed it)
---

**Finding ID Prefix:** `OPAQUEPTR`.

**Gates:**

1. A raw pointer / opaque handle originates from an FFI function (e.g., `lib_alloc()` returning `*mut Foo`) whose lifetime the C side manages.
2. The Rust side **keeps using the handle** (deref, or passes it to another FFI call) **after** an invalidating event — the matching `lib_free(p)` / `lib_destroy(p)` already ran, the owning object was closed, or the same handle is handed to the free function twice. This is a use-after-free / double-free of the *handle identity*, with **no** Rust `Drop` of Rust-allocated memory involved.
3. No documented ownership-transfer contract (single owner Rust OR single owner C) and no invalidation guard (the handle is not nulled / `take()`n after the free).

**FPs:**

- The handle is invalidated and then provably never used again (set to null, or held in `Option<NonNull<_>>` and `take()`n on free).
- C library documents a single-owner-Rust transfer (`_take_ownership`) and Rust calls it, so Rust legitimately owns the lifetime end-to-end.

**vs `FOREIGNDROP`:** if the defect is a Rust `impl Drop` (or `Box::from_raw` / `Vec::from_raw_parts` + implicit Drop) **freeing** C-owned memory through the Rust allocator, file `FOREIGNDROP` (ffi-cross-language), not `OPAQUEPTR`. `OPAQUEPTR` is strictly handle identity/validity — using or re-freeing a stale handle — with no Rust-side `Drop` of foreign memory.

**Patch:** model the handle's lifetime in the type system — wrap it in a newtype over `NonNull<Foo>` that becomes inaccessible after the invalidating call (consume `self` in the `close`/`free` wrapper, or store `Option<NonNull<Foo>>` and `take()` it on free), so a use-after-free or double-free of the handle is a compile error rather than runtime UB.
