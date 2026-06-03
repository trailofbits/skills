---
name: cluster-ffi-cross-language
kind: cluster
consolidated: false
covers:
  - cstring-dangling # CSTRDANGLE
  - abi-mismatch     # ABIMISMATCH
  - repr-c-padding   # REPRCPAD
  - packed-field-ref # PACKEDREF
  - opaque-pointer   # OPAQUEPTR
  - foreign-drop     # FOREIGNDROP
  - closure-ffi      # CLOSUREFFI
  - dyn-trait-ffi    # DYNFFI
---

# Cluster: FFI cross-language

ID prefixes: `CSTRDANGLE`, `ABIMISMATCH`, `REPRCPAD`, `PACKEDREF`, `OPAQUEPTR`, `FOREIGNDROP`, `CLOSUREFFI`, `DYNFFI`.

## Phase A

```
Grep: pattern="extern\s+\"C\"|extern\s+\{"
Grep: pattern="CString::|CStr::|CString::new"
Grep: pattern="#\[repr\((C|packed|transparent)"
Grep: pattern="#\[repr\([^\]]*packed"
Grep: pattern="bindgen|cbindgen"
Grep: pattern="\bimpl\s+Drop\s+for\s+\w+"
Grep: pattern="libc::(malloc|free)|CoTaskMem|g_malloc|CFAllocator|LocalAlloc"
Grep: pattern="\bdyn\s+Fn(Once|Mut)?\b|\bextern\s+\"C\"\s*fn\b|catch_unwind"
Grep: pattern="\bdyn\s+\w|\bBox<\s*dyn\s+\w"
Grep: pattern="\b&(?:mut\s+)?[\w.]+\.\w+"
```

Run finders in declared order.

## Deconfliction

- `PACKEDREF` vs `REPRCPAD`: unaligned field references on `#[repr(packed)]` vs uninitialized padding in `#[repr(C)]` — different UB class; both may appear in wire-format structs.
- `PACKEDREF` vs `REPRC` (unsafe-boundary): missing explicit `repr` on an FFI boundary vs taking `&field` on a known packed struct.
- `PACKEDREF` vs `PTRCAST`: unaligned reference creation vs pointer provenance / wrong-type cast.
