---
name: repr-c-padding-finder
description: Detects #[repr(C)] structs whose padding bytes leak uninitialized memory across FFI
---

**Finding ID Prefix:** `REPRCPAD`.

**Gates:**

1. `#[repr(C)]` struct with non-uniform field types creating padding (e.g., `struct { u8, u64 }` → 7 bytes padding).
2. The struct is passed by value or written via `ptr::write` to an FFI sink (network socket, file, shared memory).
3. The struct's padding is left **indeterminate** at construction — built via a normal struct literal, field-by-field assignment, or `MaybeUninit::uninit().assume_init()` with per-field writes — and then its **raw bytes** are read/sent. (`MaybeUninit::<T>::zeroed()` zeroes the whole buffer *including padding*, but `.assume_init()` is a **typed** read of `T`, and a typed copy/move of `T` is **not** guaranteed to preserve padding bytes. So zeroing reliably suppresses the leak only when the raw bytes are read from the **same** zeroed `MaybeUninit` storage — fields written through its pointer, then *that buffer's* bytes sent. Code that does `let v = MaybeUninit::<T>::zeroed().assume_init();` and then reads the bytes of `v` is **still in scope** — the `assume_init` copy may have re-poisoned the padding.)

**Why:** padding bytes are uninitialized → information disclosure across FFI.

**Patch:** read the raw bytes from a `MaybeUninit<T>` you zeroed and then wrote fields into **through its pointer** — do **not** `assume_init` the value out and then read *its* bytes (a typed copy may not preserve the zeroed padding). Better still, give the struct explicit padding fields / use a no-padding `#[repr(C)]` layout (e.g. via `zerocopy`), or serialize field-by-field instead of dumping raw bytes. `MaybeUninit::<T>::zeroed()` only initializes padding soundly when zero is also a valid bit pattern for every field.
