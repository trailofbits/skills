---
name: cstring-dangling-finder
description: Detects CString::as_ptr() pointers that escape the CString temporary's statement scope before FFI use
---

**Finding ID Prefix:** `CSTRDANGLE`.

**Bug shape (research):** `let p = CString::new("x")?.as_ptr(); c_function(p);` — the `CString` temporary Drops at the end of the `let` statement, leaving `p` dangling when the later FFI call uses it.

**Gates:**

1. `.as_ptr()` (or `.as_bytes_with_nul().as_ptr()`) on a temporary `CString` / `CStr`.
2. The raw pointer escapes the temporary's statement scope via a `let` binding, struct/callback/static storage, return value, or a callee contract that retains the pointer beyond the call.
3. The escaped pointer is passed to an `extern "C"` function or otherwise dereferenced after the `CString` has been Dropped.
4. No binding (`let cs = CString::new(...)?;`) extends the `CString`'s lifetime to enclose every pointer use, and no ownership transfer (`into_raw`) or leak is intentional.

**Common false positives to avoid:**

- `c_function(CString::new("x")?.as_ptr())` when the C callee consumes the pointer synchronously and does not retain it; the temporary lives until the end of the enclosing statement.
- `let cs = CString::new(s)?; c_function(cs.as_ptr());` where `cs` remains alive for the whole FFI use.

**Patch:** `let cs = CString::new(s)?; ffi(cs.as_ptr());`.
