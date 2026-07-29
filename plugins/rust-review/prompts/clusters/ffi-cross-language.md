---
name: cluster-ffi-cross-language
kind: cluster
consolidated: false
covers:
  - cstring-dangling # CSTRDANGLE
  - abi-mismatch     # ABIMISMATCH
  - repr-c-padding   # REPRCPAD
  - opaque-pointer   # OPAQUEPTR
  - foreign-drop     # FOREIGNDROP
  - closure-ffi      # CLOSUREFFI
  - dyn-trait-ffi    # DYNFFI
---

# Cluster: FFI cross-language

ID prefixes: `CSTRDANGLE`, `ABIMISMATCH`, `REPRCPAD`, `OPAQUEPTR`, `FOREIGNDROP`, `CLOSUREFFI`, `DYNFFI`.

## Phase A

```
rg seed: "extern\s+\"(C|system|stdcall|cdecl|win64|sysv64|aapcs|fastcall|thiscall|vectorcall|efiapi)(-unwind)?\"|extern\s+\{|\bextern\s+fn\b"
rg seed: "CString::|CStr::|CString::new"
rg seed: "#\[repr\((C|transparent)"
rg seed: "bindgen|cbindgen"
rg seed: "\bimpl\b[^{]*?\bDrop\s+for\s+\w+"
rg seed: "libc::(malloc|free)|CoTaskMem|g_malloc|CFAllocator|LocalAlloc"
rg seed: "\bdyn\s+Fn(Once|Mut)?\b|\bextern\s+\"(C|C-unwind|system)\"\s*fn\b|catch_unwind"
rg seed: "\bdyn\s+\w|\bBox<\s*dyn\s+\w"
rg seed: "\bc_void\b"                                                                  # OPAQUEPTR seed: *mut/*const c_void opaque handles
```

## Phase B — Run finders in order

Apply each pass against the Phase-A inventory; detailed detection + FP guidance live in the per-class finder files (do not re-derive them here).

1. **`CSTRDANGLE` — cstring-dangling** — `CString::as_ptr()` used after the owning `CString` (often a temporary dropped at end of statement) is gone. Seed: `CString::` / `CStr::`.
2. **`ABIMISMATCH` — abi-mismatch** — `extern` fn signature, calling convention, or type widths disagree with the foreign declaration. Seed: `extern "C"`, `bindgen`.
3. **`REPRCPAD` — repr-c-padding** — uninitialized `#[repr(C)]` padding bytes cross the FFI boundary (info leak). Seed: `#[repr(C|transparent)]`.
4. **`OPAQUEPTR` — opaque-pointer** — ownership/validity confusion over an opaque handle passed across FFI. Seed: `*mut c_void`, opaque handle types.
5. **`FOREIGNDROP` — foreign-drop** — Rust `Drop` frees memory the foreign side owns (or vice-versa): mismatched allocator/free. Seed: `impl Drop`, `libc::free` / `CoTaskMem` / `g_malloc`.
6. **`CLOSUREFFI` — closure-ffi** — Rust closure registered as a C callback without `catch_unwind` (panic across `extern "C"`) or with unbounded capture lifetimes. Seed: `dyn Fn*`, `extern "C" fn`, `catch_unwind`.
7. **`DYNFFI` — dyn-trait-ffi** — `dyn Trait` fat pointer (vtable + data) truncated to a thin pointer crossing the boundary. Seed: `Box<dyn ...>`, `dyn ...`.

## Deconfliction

- `REPRCPAD` (this cluster) vs `REPRC` (unsafe-boundary): `REPRCPAD` owns *uninitialized padding bytes leaking across FFI*; `REPRC` owns *general layout / `#[repr]` soundness*. File `REPRCPAD` when the defect is padding disclosure at the boundary.
- `OPAQUEPTR` vs `FOREIGNDROP`: handle *identity/validity* confusion vs *who calls free*. An opaque handle whose `Drop` frees foreign-owned memory is `FOREIGNDROP`; mere use-after-invalidate of the handle is `OPAQUEPTR`.
- `CLOSUREFFI` vs `DYNFFI`: closure *trampoline / panic-unwind* hazard vs a `dyn Trait` *fat-pointer / vtable* crossing the boundary. A `Box<dyn Fn>` passed as a callback is `CLOSUREFFI`; a `dyn Trait` object whose vtable crosses FFI is `DYNFFI`.
- `CSTRDANGLE` vs `FOREIGNDROP`: a Rust-owned `CStr` whose lifetime ends too early vs the foreign side freeing a buffer Rust still references.
