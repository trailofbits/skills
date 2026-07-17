---
name: panic-unwind-unsafe-finder
description: Detects panic-unsafe unsafe container mutation where unwinding leaves stale len/capacity and later Drop/clear causes UAF or double-free
---

**Finding ID Prefix:** `PANICUNWIND`.

**Bug shape:** A safe-facing type owns buffer state (`len`, `capacity`, initialized element count) updated through `unsafe` (`ptr::write`, `drop_in_place`, manual grow). A panic during the mutation body unwinds while the invariants still describe the *pre-mutation* layout. A later `Drop`, `clear`, `into_iter` drop, or retry of the same method revisits already-freed slots, causing double-free (CWE-415) or UAF (CWE-416). The canonical fix commits `len` before the drop loop or guards the unwind; see Patch.

**Verification gates (ALL must pass):**

1. **Unsafe container:** custom `Vec`-like / growable buffer / `clear` / `push` / `insert` / iterator `Drop` with `unsafe { }` touching element storage (not merely wrapping `std::vec::Vec` without custom drop loops).
2. **Panic point before invariant commit:** between the last durable metadata update (`set_len`, `self.len =`, `capacity =`) and the end of the operation, a step can unwind — `drop_in_place`, `Drop` of moved values, allocation (`reserve`, `grow`, `alloc`), fallible `Clone`, indexing, or `.unwrap()` on the mutation path.
3. **Late metadata update:** `len` / initialized count / "logical empty" flag is updated **after** that panic point (e.g., `for i in 0..len { drop_in_place(...); }` then `self.len = 0`; or `self.len += 1` before `ptr::write` completes).
4. **Second free reachable:** another `Drop` / `clear` / partial consume on the same value can run after a caught panic (`catch_unwind`) or during unwind (same-function retry, `Drop` on `self`, closure epilogue).

**FPs to reject:**

- `len` / capacity / guard state is committed **before** any panic-prone step (e.g. `let len = self.len; self.len = 0;` then drop loop).
- `ManuallyDrop`, `mem::forget`, or `ptr::read` + `forget` removes the second `Drop` path.
- Operation is provably panic-free (only `Copy` types, no custom `Drop`, no allocation).
- Entire mutation runs under `abort` (no unwinding) — note in narrative, do not file as memory corruption.
- Covered by `CLOSUREPANIC` (user `Fn` between two `ptr::read`/`write` pairs) or `DROPPANIC` (panic inside `impl Drop` itself, not container bookkeeping).

**Search patterns:**

```
drop_in_place
\bself\.len\s*=
set_len\s*\(
\bfor\s+\w+\s+in\s+0\.\.(\w+\.)?len
\.clear\s*\(
into_iter|IntoIter
catch_unwind
```

**Patch:** commit `len = 0` (or the target length) before dropping; wrap the panic-prone tail in `scopeguard::guard` / a private `DropGuard` that restores or zeroes `len` on unwind; or delegate storage to `std::vec::Vec` when custom drop loops are unnecessary.

Distinct from `UAF` (raw pointer outlives source `Drop`) and `DFREE` (`ptr::read` duplicates ownership without a panic): `PANICUNWIND` requires **stale container metadata across unwind**, not a dangling pointer or bitwise duplicate alone.
