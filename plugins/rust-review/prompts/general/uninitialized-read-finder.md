---
name: uninitialized-read-finder
description: Detects reads from uninitialized memory in Rust unsafe blocks
---

**Finding ID Prefix:** `UNINITREAD`.

**Bug shape:** `MaybeUninit::<T>::assume_init()` (or `assume_init_ref`/`assume_init_mut`) called before every field of `T` is written. Also: deprecated `mem::uninitialized::<T>()` is **always** UB for non-zeroable types.

**Verification gates:**

1. **Trigger:** `assume_init*`, `mem::uninitialized`, or transmute of `MaybeUninit::uninit()` into `T`.
2. **Initialization incomplete:** at least one field of `T` (recursively, for nested structs) has no write reaching the `assume_init` site on at least one path.
3. **Type forbids uninit:** `T` is not `MaybeUninit<U>`, not a primitive integer that allows any bit pattern, and not zero-padded by the caller.

**FPs:**

- `T = MaybeUninit<U>` — `assume_init` is on the inner wrapper.
- Caller writes all fields via `ptr::write` (verify by tracing field accesses).
- `T = u8` / similar — all bit patterns are valid.

**Search patterns:**

```
\bassume_init(_ref|_mut)?\b
mem::uninitialized\b
MaybeUninit::(uninit|new|zeroed)
```

**Patch:** initialize each field with `MaybeUninit::write` or `addr_of_mut!(...).write(...)` before `assume_init`.
