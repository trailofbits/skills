---
name: refcell-borrow-panic-finder
description: Detects RefCell borrow/borrow_mut that panics at runtime due to overlapping borrows driven by reentrancy or callbacks
---

**Finding ID Prefix:** `REFCELLPANIC`.

**Bug shape:** `RefCell::borrow`/`borrow_mut` (commonly behind `Rc<RefCell<_>>`) panics at runtime when an incompatible borrow is already live. Reentrancy via callbacks, recursion, observers, or `Drop` running while a borrow is held — especially when an attacker controls the call sequence — turns a logic slip into a panic/DoS. (Drop-time borrow panics route to `DROPPANIC`; cross-thread reentrancy to the concurrency-locking reentrancy classes.)

**Gates:**

1. A `borrow_mut` (or `borrow`) is held across a call that can re-enter and borrow the same cell (callback, recursion, observer, `Drop`).
2. That path is reachable on untrusted-driven input.

**FPs:**

- `try_borrow`/`try_borrow_mut` used and the error handled.
- Borrows provably non-overlapping (no call out while a borrow is held).
- Single-threaded with no reentrancy path.

**Patch:** prefer `try_borrow*` with error handling; narrow each borrow's scope so none is held across a call-out; restructure to avoid reentrant borrows.
