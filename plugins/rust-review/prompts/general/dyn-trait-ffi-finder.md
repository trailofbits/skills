---
name: dyn-trait-ffi-finder
description: Detects fat-pointer trait objects (dyn Trait) crossing extern "C" boundaries
---

**Finding ID Prefix:** `DYNFFI`.

**Bug shape:** `&dyn Trait`, `&mut dyn Trait`, `*const dyn Trait`, `*mut dyn Trait`, and `Box<dyn Trait>` are **fat pointers** — two-word values containing a data pointer and a vtable pointer. The layout of this pair is not part of Rust's ABI guarantees: it is `#[repr(Rust)]`, can change between compiler versions, can change between toolchain builds with different vtable optimizations, and cannot be reconstructed on the C side. Passing a fat pointer through `extern "C" fn` or storing one in a `#[repr(C)]` struct that crosses FFI is unsound.

The same applies to `&[T]` / `&mut [T]` / `&str` (also fat pointers — `(data, len)`), but those are usually flagged by ABI-mismatch tooling; this finder focuses on `dyn` specifically because it is the layout most likely to silently change.

**Verification gates (ALL must pass):**

1. **`dyn` at FFI boundary:** an `extern "C" fn` signature, a `#[repr(C)]` struct field, or an FFI-bound trait object — `&dyn Trait`, `&mut dyn Trait`, `*const dyn Trait`, `*mut dyn Trait`, `Box<dyn Trait>`, `Arc<dyn Trait>`, `Rc<dyn Trait>` — appears as parameter, return, or field.
2. **Crosses the boundary:** the fat pointer is the in-Rust representation of a value handed to or received from C (look for `extern "C" {` blocks declaring the function, or `#[no_mangle] pub extern "C" fn`).
3. **Not an opaque-pointer pattern:** the value is *not* a `*mut c_void` plus a vtable struct passed separately (which is the sound idiom — covered as the correct pattern, not flagged).

**FPs to reject:**

- `*mut c_void` paired with a `#[repr(C)]` `Vtable` struct holding function pointers — sound pattern.
- Internal trait objects inside the Rust side, not exposed in `extern "C"` signatures.
- C-side opaque handle (`*mut OpaqueT`) that just happens to point at a Rust trait object — sound *if* C only ever passes it back to Rust.

**Search patterns:**

```
extern\s+"C"\s*\{
\bextern\s+"C"\s*fn\b[^{]*\bdyn\b
#\[repr\([^]]*\bC\b
\bBox<\s*dyn\s+\w
\bdyn\s+\w
```

`Grep` is line-oriented (ripgrep default), so a body-spanning `extern\s+"C"\s*\{[^}]*\bdyn\b` or `#\[repr\(C\)\][\s\S]{0,200}\bdyn\b` does **not** match across a multi-line `extern` block or struct definition (the `{` / attribute and the `dyn` land on different lines). Match the `extern "C" {` / `#[repr(C)]` opener and **Read** the block to enumerate its `dyn`-typed parameters, returns, and fields.

**Patch:** replace `&dyn Trait` with a `*mut c_void` + `#[repr(C)] struct Vtable { f1: extern "C" fn(...), ... }` pair; or with a single concrete `#[repr(C)]` struct type when the trait has one implementation worth exposing. Document the layout contract in a `// SAFETY:` comment.
