---
name: cstring-dangling-finder
description: Detects CString::as_ptr() passed to FFI where the CString is dropped before the call returns
---

**Finding ID Prefix:** `CSTRDANGLE`.

**Bug shape (research):** `c_function(CString::new("x")?.as_ptr())` — the `CString` is a temporary and Drops at the end of the statement; the FFI call may use the pointer past that point.

**Gates:**

1. `.as_ptr()` (or `.as_bytes_with_nul().as_ptr()`) on a temporary `CString` / `CStr`.
2. The pointer is passed to an `extern "C"` function.
3. No binding (`let cs = CString::new(...)?;`) extends the `CString`'s lifetime to enclose the FFI call.

**Patch:** `let cs = CString::new(s)?; ffi(cs.as_ptr());`.
