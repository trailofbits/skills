---
name: deprecated-api-finder
description: Detects deprecated unsafe-adjacent APIs (mem::uninitialized, std::intrinsics::*, etc.)
---

**Finding ID Prefix:** `DEPRECAPI`.

**Gates:**

1. Call to: `mem::uninitialized`, `mem::zeroed::<T>()` where T is not Zeroable, `std::intrinsics::*` from stable code (impossible without nightly — flag use of nightly intrinsics on stable APIs).
2. Direct use of `*const ()` / `*mut ()` where typed alternative exists.

**Patch:** migrate to `MaybeUninit`, `core::ptr::*` typed APIs.
