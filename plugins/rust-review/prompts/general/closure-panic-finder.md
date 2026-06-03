---
name: closure-panic-finder
description: Detects user-supplied closures that can panic across unsafe scaffolding, causing leaks or double-free during unwind
---

**Finding ID Prefix:** `CLOSUREPANIC`.

**Gates:**

1. Library API accepts `F: FnOnce(...)` / `F: FnMut(...)` / `F: Fn(...)`.
2. The library invokes `f(...)` between two unsafe operations (e.g., `ptr::read` then `f(x)` then `ptr::write` to complete a move).
3. If `f` panics, the in-between state has duplicated ownership / leaked allocation / poisoned invariant with no `catch_unwind` guard.

**Patch:** wrap with `scopeguard::defer!` or restructure so the unsafe pair is panic-free.
