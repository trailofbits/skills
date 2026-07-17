---
name: deprecated-api-finder
description: Detects deprecated unsafe-adjacent APIs (mem::uninitialized, std::intrinsics::*, etc.)
---

**Finding ID Prefix:** `DEPRECAPI`.

**Gates:**

1. Call to `mem::uninitialized::<T>()` — genuinely deprecated since Rust 1.39 (use `MaybeUninit`). This is the canonical in-scope target.
2. Use of `std::intrinsics::*` or `#![feature(core_intrinsics)]` — not "deprecated", but it pins the crate to a **nightly** toolchain (it cannot compile on stable); flag as a portability/hygiene concern.

**Out of scope** (do NOT flag here):

- `mem::zeroed` is **not** deprecated. Zeroing a type with no valid all-zero representation (`NonNull`, references, many enums) is an *invalid-value* soundness bug that belongs to the `uninitialized-read` (UNINITREAD) pass, not this one. (Note: `bool` is **not** such a type — its all-zero byte is `false`, so `mem::zeroed::<bool>()` is sound; `bool`'s hazard is an *arbitrary* non-`0`/`1` byte, not zeroing.)
- `*const ()` / `*mut ()` are idiomatic type-erased pointers (FFI handles, vtable erasure), not deprecated APIs.

**FPs to reject:** occurrences inside string literals/comments, or in `#[cfg(test)]` fixtures. A `#[allow(deprecated)]` annotation clears only the *deprecation* aspect (DEPRECAPI) — it does **not** clear the underlying soundness bug: `#[allow(deprecated)] mem::uninitialized::<T>()` for a `T` with no valid uninit representation is still UB (rustc's `invalid_value` lint still fires), which the `uninitialized-read` (UNINITREAD) pass must still report. So treat `#[allow(deprecated)]` as suppressing the DEPRECAPI finding only, never the invalid-value/UB concern.

**Search patterns:**

```
\bmem::uninitialized\b|\bstd::mem::uninitialized\b
core::intrinsics::|std::intrinsics::|feature\(core_intrinsics\)
```

**Patch:** migrate `mem::uninitialized` to `MaybeUninit`; replace nightly intrinsics with their stabilized equivalents (or document the nightly requirement).
