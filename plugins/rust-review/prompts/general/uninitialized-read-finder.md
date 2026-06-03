---
name: uninitialized-read-finder
description: Detects reads from uninitialized memory in Rust unsafe blocks
---

**Finding ID Prefix:** `UNINITREAD`.

**Bug shape:** `MaybeUninit::<T>::assume_init()` (or `assume_init_ref`/`assume_init_mut`) called before every field of `T` is written. Also: deprecated `mem::uninitialized::<T>()` is **always** UB for non-zeroable types.

**Verification gates:**

1. **Trigger:** `assume_init*`, `mem::uninitialized`, or transmute of `MaybeUninit::uninit()` into `T`.
2. **Initialization incomplete:** at least one field of `T` (recursively, for nested structs) has no write reaching the `assume_init` site on at least one path.
3. **Initialization required:** `T` is not `MaybeUninit<U>`, and the value was not initialized by a dominating write, `MaybeUninit::new`, or `MaybeUninit::zeroed`/`write_bytes` where zeroed bytes are valid for `T`.

**FPs:**

- `T = MaybeUninit<U>` — `assume_init` is on the inner wrapper.
- Caller writes all fields via `ptr::write` (verify by tracing field accesses).
- Primitive integers (`u8`, `usize`, etc.) still must be initialized. All bit patterns may be valid, but a value obtained from uninitialized memory is UB; only suppress when the bytes were actually written or otherwise initialized.

**Search patterns:**

```
\bassume_init(_ref|_mut)?\b
mem::uninitialized\b
MaybeUninit::(uninit|new|zeroed)
```

**Patch:** initialize each field with `MaybeUninit::write` or `addr_of_mut!(...).write(...)` before `assume_init`.
