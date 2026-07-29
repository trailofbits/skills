---
name: closure-ffi-finder
description: Detects Rust closures passed to extern "C" callbacks without panic isolation
---

**Finding ID Prefix:** `CLOSUREFFI`.

**Bug shape:** A Rust closure (or function pointer derived from one) is registered as a C callback via FFI. When the C library invokes the callback and the Rust closure panics, the unwind crosses the `extern "C"` boundary into C — **undefined behavior before Rust 1.81, and a process `abort` since Rust 1.81** (a compiler-version change, *not* the 2024 edition — edition-2021 code on rustc ≥ 1.81 already aborts; still a DoS on a server). Two derivatives: (a) the closure captures `&'a T` references whose lifetime cannot be enforced by Rust on the C side, producing UAF when C invokes the callback after the captures' scope ends; (b) `Box<dyn FnMut>` is `into_raw`'d and passed as user-data without a paired `from_raw` in a deregister path, producing leaks plus the panic-unwind hazard.

**Verification gates (ALL must pass):**

1. **Closure→C call:** Rust closure (`|...| { ... }`, `Box::new(|...| ...)`, `Box<dyn Fn(...)>`) converted to a function-pointer-typed argument of an `extern "C" fn(..)` or registered through a `*mut c_void` + trampoline pattern (`extern "C" fn trampoline(... user_data: *mut c_void)`).
2. **For the panic hazard, no `catch_unwind` guard:** the trampoline (or the closure body itself if directly `extern "C"`) does not wrap the call in `std::panic::catch_unwind` and convert the result to an error code / safe-default return. (This gate scopes the *panic* sub-case only — the capture-UAF and leak derivatives in gate 3 are independent of `catch_unwind` and are filed regardless of whether a guard exists.)
3. **A hazard is present — at least one of:** *(panic)* the closure body calls into Rust code that *can* panic — `unwrap`/`expect`/indexing/`assert!`/arithmetic on untrusted inputs/allocations (the unwind-across-FFI hazard); *(capture-UAF, derivative (a))* the closure captures `&'a T` references whose lifetime the C side can outlive; or *(leak, derivative (b))* a `Box<dyn Fn*>` is `into_raw`'d / handed over as user-data with no paired `from_raw` on a deregister path. If the body is provably panic-free (`no_std` arithmetic in `wrapping_*` form, no allocs, no `unwrap`/`expect`/indexing/`assert!`) **and** neither derivative (a) nor (b) applies, do not file. Do not assign or lower a severity yourself — that is the fp+severity judge's job; your decision here is file / don't-file on whether any of these hazards is reachable.

**FPs to reject:**

- Trampoline already uses `catch_unwind` and converts to a C-friendly error code.
- The trampoline body is provably panic-free (gate 3 already covers this), or the callback runs in a non-server / non-DoS-relevant context. (Note: `#[unwind(abort)]` is **not** a valid guard — that attribute was removed years ago and does not compile. And `-C panic=abort` is **not** a mitigation: under it a panic in the callback still aborts the whole process — the same DoS the bug shape warns about — and `catch_unwind` becomes a no-op.)
- The callback is registered for `signal()` and the issue is signal-safety (covered by `REENTRANT`).

**Search patterns:**

```
extern\s+"C"\s*\{
\bextern\s+"(C|C-unwind|system)"\s*fn\b
\bBox::into_raw\b
\bdyn\s+Fn(Once|Mut)?\b
catch_unwind
```

The first pattern matches only the `extern "C" {` block opener — ripgrep is line-oriented, so the old body-spanning `extern "C" \{[^}]*fn...fn...\)` could not match a multi-line block; Read the located block to enumerate its function-pointer callback params instead.

For each hit, find the trampoline and check for `catch_unwind`.

**Patch:** wrap the closure body inside the `extern "C"` trampoline with `std::panic::catch_unwind(AssertUnwindSafe(|| { ... }))` and translate `Err` to a C error code (or to the C library's documented failure return). For `Box<dyn FnMut>` user-data, ensure the deregister path calls `Box::from_raw` exactly once.
