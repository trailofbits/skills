---
name: repr-c-padding-finder
description: Detects #[repr(C)] structs whose padding bytes leak uninitialized memory across FFI
---

**Finding ID Prefix:** `REPRCPAD`.

**Gates:**

1. `#[repr(C)]` struct with non-uniform field types creating padding (e.g., `struct { u8, u64 }` → 7 bytes padding).
2. The struct is passed by value or written via `ptr::write` to an FFI sink (network socket, file, shared memory).
3. The struct was constructed without explicit padding zeroing (`MaybeUninit::zeroed().assume_init()` or struct literal with all fields — but padding still uninit).

**Why:** padding bytes are uninitialized → information disclosure across FFI.

**Patch:** zero the buffer explicitly via `MaybeUninit::<T>::zeroed().assume_init()` (sound only if zero is a valid value for every field).
