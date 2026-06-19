---
name: invalid-free-finder
description: Detects invalid-free via assignment to dereferenced pointer over uninitialized memory
---

**Finding ID Prefix:** `INVFREE`.

**Bug shape (from research):** `alloc()` returns uninitialized memory. Writing `*ptr = new_val` invokes `Drop` on the **previous** (garbage) value to prevent leaks. The previous value is uninitialized bytes — Rust calls `Drop` on random memory.

**Verification gates:**

1. **Uninit allocation:** `ptr` originates from raw `alloc`, `MaybeUninit::uninit().as_mut_ptr()`, or similar.
2. **Assignment via deref:** `*ptr = expr` syntax (NOT `ptr::write(ptr, expr)`).
3. **Drop type:** the value type has a non-trivial `Drop`.
4. **No prior init:** no `ptr::write` or analogous initialization preceded the assignment on this control-flow path.

**FPs to reject:**

- Uses `ptr::write` (correct primitive — overwrites without Drop on previous value).
- Type is `Copy` and has no Drop.
- `MaybeUninit::write` (explicitly handles this).

**Search patterns:**

```
alloc::alloc\s*\(|MaybeUninit::uninit\(\)
\*\s*[\w.]+\s*(\([^)]*\))?\s*=[^=]
ptr::write\b
```

**Patch:** replace `*ptr = val` with `ptr::write(ptr, val)`.
