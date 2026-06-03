---
name: drop-panic-finder
description: Detects panic possibility inside Drop impls (double-panic abort) or Mutex poisoning paths
---

**Finding ID Prefix:** `DROPPANIC`.

**Gates:**

1. `impl Drop for T` exists.
2. The `drop` method body contains an operation that can panic: `.unwrap()`, `.expect()`, arithmetic, indexing, `assert!`, allocation, or any `panic!`.
3. The type is constructed in user-reachable code paths (not test-only).

**Why it matters:** if `Drop` panics during stack unwinding from another panic, the process aborts. If `Drop` panics holding a `Mutex` guard, the mutex is poisoned and downstream `.lock().unwrap()` calls panic too — a propagating DoS.

**Patch:** log-and-swallow inside `Drop`; never `.unwrap()` in a destructor.
