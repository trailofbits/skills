---
name: cluster-layout-safety
kind: cluster
consolidated: false
covers:
  - packed-field-ref # PACKEDREF
---

# Cluster: Type layout safety

Undefined behavior from in-memory type layout the compiler does not always reject: references to fields of `#[repr(packed)]` structs (including implicit borrows via auto-deref). Common in wire-format and C-layout-matched structs, independent of whether the crate uses FFI.

ID prefixes: `PACKEDREF`.

## Phase A

```
rg seed: "#\[repr\([^\]]*packed"
rg seed: "&(?:mut\s+)?[\w.]+\.(?:\w+|\d+)"
```

Run finders in declared order.
