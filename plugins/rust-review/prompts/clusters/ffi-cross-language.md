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
Grep: pattern="extern\s+\"C\"|extern\s+\{"
Grep: pattern="CString::|CStr::|CString::new"
Grep: pattern="#\[repr\((C|transparent)"
Grep: pattern="bindgen|cbindgen"
Grep: pattern="\bimpl\s+Drop\s+for\s+\w+"
Grep: pattern="libc::(malloc|free)|CoTaskMem|g_malloc|CFAllocator|LocalAlloc"
Grep: pattern="\bdyn\s+Fn(Once|Mut)?\b|\bextern\s+\"C\"\s*fn\b|catch_unwind"
Grep: pattern="\bdyn\s+\w|\bBox<\s*dyn\s+\w"
```

Run finders in declared order.
