---
name: deprecated-api-finder
description: Detects deprecated unsafe-adjacent APIs (mem::uninitialized, std::intrinsics::*, etc.)
---

**Finding ID Prefix:** `DEPRECAPI`.

**Gates:**

1. Call to `mem::uninitialized::<T>()` — genuinely deprecated since Rust 1.39 (use `MaybeUninit`). This is the canonical in-scope target.
2. Use of `std::intrinsics::*` or `#![feature(core_intrinsics)]` — not "deprecated", but it pins the crate to a **nightly** toolchain (it cannot compile on stable); flag as a portability/hygiene concern.

**Out of scope** (do NOT flag here):

- `mem::zeroed` is **not** deprecated. Zeroing a type with no valid all-zero representation (`NonNull`, references, `bool`, many enums) is an *invalid-value* soundness bug that belongs to the `uninitialized-read` (UNINITREAD) pass, not this one.
- `*const ()` / `*mut ()` are idiomatic type-erased pointers (FFI handles, vtable erasure), not deprecated APIs.

**FPs to reject:** occurrences inside `#[allow(deprecated)]`-annotated code, inside string literals/comments, or in `#[cfg(test)]` fixtures.

**Search patterns:**

```
\bmem::uninitialized\b|\bstd::mem::uninitialized\b
core::intrinsics::|std::intrinsics::|feature\(core_intrinsics\)
```

**Patch:** migrate `mem::uninitialized` to `MaybeUninit`; replace nightly intrinsics with their stabilized equivalents (or document the nightly requirement).
