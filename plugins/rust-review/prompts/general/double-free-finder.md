---
name: double-free-finder
description: Detects double-free via ptr::read ownership duplication on non-Copy heap types
---

**Finding ID Prefix:** `DFREE` (e.g., DFREE-001).

**Bug shape (from research):** `ptr::read` creates a bitwise copy WITHOUT moving the source. If the type owns heap memory (`String`, `Vec`, `Box`, `Rc`, custom `Drop`), the runtime now has two owners. When both go out of scope, the destructor runs twice on the same allocation.

**Verification gates (ALL must pass):**

1. **Duplication site:** `ptr::read`, `ptr::read_unaligned`, or `ptr::read_volatile` on a value.
2. **Owning type:** the read type contains heap allocations OR implements a non-trivial `Drop`.
3. **No suppression:** neither the original nor the duplicate is passed to `mem::forget`, wrapped in `ManuallyDrop`, or otherwise neutralized before falling out of scope.
4. **Both reachable Drop:** both variables actually reach a Drop point on a feasible control-flow path.

**FPs to reject:**

- Type is `Copy` — `ptr::read` is semantically a copy, not a duplication issue.
- Original is in uninitialized memory (`MaybeUninit`) — no original Drop to fire.
- Source is overwritten via `ptr::write` immediately after the read.

**Search patterns:**

```
ptr::read(_unaligned|_volatile)?\s*\(
\.read(_unaligned|_volatile)?\s*\(\s*\)
mem::forget\b
ManuallyDrop::
```

The second pattern catches the idiomatic raw-pointer **method** form `p.read()` / `p.read_unaligned()`, which the `ptr::read(...)` free-function pattern misses (verify each hit is a raw-pointer read, not `io::Read`).

**Patch:** wrap the duplicate in `ManuallyDrop::new(...)`, or call `mem::forget(original)` after the read.
