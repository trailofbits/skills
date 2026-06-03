---
name: opaque-pointer-finder
description: Detects Rust-side raw pointers to C-owned memory used as if Rust-managed (double-free across FFI, UAF)
---

**Finding ID Prefix:** `OPAQUEPTR`.

**Gates:**

1. Raw pointer originates from an FFI function (e.g., `lib_alloc()` returning `*mut Foo`).
2. Rust code wraps it in `Box::from_raw`, `Vec::from_raw_parts`, or similar, then Drops — but the C side ALSO owns / frees the same memory (via `lib_free`).
3. No documented ownership-transfer contract (single owner Rust OR single owner C).

**FPs:**

- `Box::from_raw` paired with `Box::into_raw` on the same lifecycle (Rust manages start-to-end).
- C library exposes an explicit `_take_ownership` API and Rust calls it.

**Patch:** never `from_raw` over C-owned memory; expose Rust-side as `*const Foo` newtype with explicit `Drop` calling the C free.
