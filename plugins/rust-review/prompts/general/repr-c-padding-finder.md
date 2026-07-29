---
name: repr-c-padding-finder
description: Detects #[repr(C)] structs whose padding bytes leak uninitialized memory across FFI
---

**Finding ID Prefix:** `REPRCPAD`.

**Gates:**

1. `#[repr(C)]` struct with non-uniform field types creating padding (e.g., `struct { u8, u64 }` → 7 bytes padding).
2. The struct is passed by value or written via `ptr::write` to an FFI sink (network socket, file, shared memory).
3. The struct's padding is left **indeterminate** at construction — built via a normal struct literal, field-by-field assignment, or `MaybeUninit::uninit().assume_init()` with per-field writes — and then its **raw bytes** are read/sent. (`MaybeUninit::<T>::zeroed()` zeroes the whole buffer *including padding*, but that only suppresses the leak when the bytes are read from the **same** `MaybeUninit` storage **in place, with no intervening move**. **Any** typed move re-poisons the padding — not only `let v = MaybeUninit::<T>::zeroed().assume_init();` then reading `v`'s bytes (the `assume_init` typed copy drops padding), but even returning the still-`MaybeUninit<T>` buffer from a constructor `fn`: a move of `MaybeUninit<T>` is **field-wise**, so padding is *not* copied. Verified empirically on rustc 1.88 release builds — after such a move the padding held garbage. So a `zeroed()` value that is returned/stored/`assume_init`'d before its bytes are read is still in scope for this finding.)

**Why:** padding bytes are uninitialized → information disclosure across FFI.

**Patch:** prefer a layout/serialization with **no padding to leak**: add explicit padding fields, derive a no-padding contract with `zerocopy::IntoBytes` (which fails to compile if padding exists), or serialize field-by-field instead of dumping raw bytes. If you must zero-and-dump, do it **in place with no intervening move**: `let mut buf = MaybeUninit::<T>::uninit(); ptr::write_bytes(buf.as_mut_ptr() as *mut u8, 0, size_of::<T>());` then write fields through `buf.as_mut_ptr()` and read bytes via `buf.as_ptr()` **in the same scope** — never `assume_init` the value out, and never return/move the buffer before reading (a typed *or* `MaybeUninit` move is field-wise and re-poisons padding — verified on release builds).
