---
name: foreign-drop-finder
description: Detects impl Drop on Rust types wrapping FFI-allocated memory that mistakenly calls Rust deallocators
---

**Finding ID Prefix:** `FOREIGNDROP`.

**Bug shape:** A Rust struct wraps a pointer allocated by a foreign allocator — `libc::malloc`, `g_malloc`, `CFAllocator`, `LocalAlloc`, `CoTaskMemAlloc`, `cudaMalloc`, language-VM allocators (PyO3 `Py`, napi-rs `JsObject`, JNI), or a C library's bespoke allocator. Its `Drop` impl (or auto-derived `Box`/`Vec` ownership) routes the free through the Rust global allocator (`Box::from_raw`, `Vec::from_raw_parts`, `dealloc`, `mem::drop`) instead of the matching foreign deallocator. This is an invalid-free at the allocator level: the Rust allocator hands the pointer to a heap it does not own.

The inverse — `extern "C" fn` *takes* a `Box<T>` allocated by Rust and returns it to C — is covered by ABI/ownership rules and not in scope here. This finding focuses on the Rust-side `Drop`.

**Verification gates (ALL must pass):**

1. **Struct holds raw pointer from FFI:** field of type `*mut T`/`*const T`/`NonNull<T>` populated from a foreign allocator (look upward for `libc::malloc`, `CString::into_raw` from foreign source, `CoTaskMemAlloc`, etc.) — confirm by tracing the constructor or `From<*mut T>` impl.
2. **`Drop` route:** the type has an explicit `impl Drop for X` whose body calls `Box::from_raw(self.ptr)`, `Vec::from_raw_parts(...)`, `alloc::dealloc(...)`, `drop(Box::from_raw(...))`, or implicitly via a `Box<T>` field of the wrong allocator.
3. **No matching foreign free:** there is no call to the foreign allocator's `free` (e.g., `libc::free`, `g_free`, `CFRelease`, `LocalFree`, `CoTaskMemFree`, `cudaFree`) before/instead.

**FPs to reject:**

- Rust-allocated pointer routed through `Box::from_raw` — that's the correct symmetry.
- Foreign-allocated pointer with `Drop` that calls the foreign free (correct).
- Type is `#[repr(C)]` and ownership is *transferred to C* — i.e., this side merely views the pointer (`PhantomData<&'a T>`); no `Drop` needed.
- Allocator is `jemalloc`/`mimalloc` configured as Rust's global allocator — symmetric with `Box::from_raw`.

**Search patterns:**

```
\bimpl\b[^{]*?\bDrop\s+for\s+\w+
\bBox::from_raw\b|\bVec::from_raw_parts\b|\bdealloc\s*\(
\blibc::(malloc|calloc|realloc|strdup)\b
CoTaskMemAlloc|LocalAlloc|GlobalAlloc[^:]|CFAllocator|g_malloc
```

Cross-reference: types whose constructors flow from a foreign allocator AND whose `Drop` flows into Rust's allocator.

**Patch:** replace the Rust dealloc with the foreign allocator's matching free (`libc::free`, `g_free`, `CoTaskMemFree`, etc.); or store an `unsafe fn drop_fn(*mut T)` alongside the pointer and call it in `Drop`. Document the allocator pairing in a `// SAFETY:` comment.
