---
name: closure-ffi-finder
description: Detects Rust closures passed to extern "C" callbacks without panic isolation
---

**Finding ID Prefix:** `CLOSUREFFI`.

**Bug shape:** A Rust closure (or function pointer derived from one) is registered as a C callback via FFI. When the C library invokes the callback and the Rust closure panics, the unwind crosses the `extern "C"` boundary into C — undefined behavior in editions prior to 2024, and `abort` since (still undesirable on a server). Two derivatives: (a) the closure captures `&'a T` references whose lifetime cannot be enforced by Rust on the C side, producing UAF when C invokes the callback after the captures' scope ends; (b) `Box<dyn FnMut>` is `into_raw`'d and passed as user-data without a paired `from_raw` in a deregister path, producing leaks plus the panic-unwind hazard.

**Verification gates (ALL must pass):**

1. **Closure→C call:** Rust closure (`|...| { ... }`, `Box::new(|...| ...)`, `Box<dyn Fn(...)>`) converted to a function-pointer-typed argument of an `extern "C" fn(..)` or registered through a `*mut c_void` + trampoline pattern (`extern "C" fn trampoline(... user_data: *mut c_void)`).
2. **No `catch_unwind` guard:** the trampoline (or the closure body itself if directly `extern "C"`) does not wrap the call in `std::panic::catch_unwind` and convert the result to an error code / safe-default return.
3. **Untrusted callable surface:** the closure body calls into Rust code that *can* panic — `unwrap`/`expect`/indexing/`assert!`/arithmetic on untrusted inputs/allocations. (If the body is provably panic-free — `no_std` arithmetic in `wrapping_*` form, no allocs, no panics — note as low severity or skip.)

**FPs to reject:**

- Trampoline already uses `catch_unwind` and converts to a C-friendly error code.
- Closure is `extern "C"` with `#[unwind(abort)]` or the crate is built with `-C panic=abort` AND that is documented.
- The callback is registered for `signal()` and the issue is signal-safety (covered by `REENTRANT`).

**Search patterns:**

```
extern\s+"C"\s*\{[^}]*fn[^}]*fn[^}]*\)
\bextern\s+"C"\s*fn\b
\bBox::into_raw\s*\([^)]*Box::new\s*\(\s*\|
\bdyn\s+Fn(Once|Mut)?\b
catch_unwind
```

For each hit, find the trampoline and check for `catch_unwind`.

**Patch:** wrap the closure body inside the `extern "C"` trampoline with `std::panic::catch_unwind(AssertUnwindSafe(|| { ... }))` and translate `Err` to a C error code (or to the C library's documented failure return). For `Box<dyn FnMut>` user-data, ensure the deregister path calls `Box::from_raw` exactly once.
