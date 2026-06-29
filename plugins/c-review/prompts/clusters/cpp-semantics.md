---
name: cluster-cpp-semantics
kind: cluster
consolidated: false
gate: is_cpp
covers:
  - init-order             # INIT
  - iterator-invalidation  # ITER
  - exception-safety       # EXCEPT
  - move-semantics         # MOVE
  - smart-pointer          # SPTR
  - virtual-function       # VIRT
  - lambda-capture         # LAMBDA
---

# Cluster: C++ semantics (gated on `is_cpp`)

Seven bug classes that only apply to C++. Share a common inventory of class definitions, smart-pointer uses, container operations, and exception paths.

ID prefixes: `INIT`, `ITER`, `EXCEPT`, `MOVE`, `SPTR`, `VIRT`, `LAMBDA`.

---

## Phase A — Seed targets

```
Grep: pattern="\\b(class|struct)\\s+\\w+\\s*(?:final\\s*)?(?::\\s*[^{]+)?\\s*\\{"
Grep: pattern="\\b(virtual|override|final)\\b"
Grep: pattern="\\b(unique_ptr|shared_ptr|weak_ptr|auto_ptr|make_unique|make_shared)\\b"
Grep: pattern="\\bstd::(move|forward)\\s*\\("
Grep: pattern="\\[(=|&|[^]]*)\\]\\s*(?:\\(|mutable|->|\\{)"   # lambda captures
Grep: pattern="\\b(push_back|emplace_back|insert|erase|clear|resize|reserve|begin|end)\\s*\\("
Grep: pattern="\\b(throw|try|catch|noexcept)\\b"
Grep: pattern="static\\s+(?:const\\s+)?[A-Z]\\w+\\s+\\w+"       # potential static init
```

Keep as `cpp_sites`.

---

## Phase B — Passes in order (reuse `cpp_sites`)

1. **`INIT` — Static init order fiasco**

2. **`VIRT` — Virtual function issues**
   Non-virtual destructors on polymorphic bases, calling virtuals from ctor/dtor.

3. **`SPTR` — Smart-pointer misuse**
   `shared_ptr` cycles, `unique_ptr` ownership transfer errors, double-delete from raw-pointer mixing.

4. **`MOVE` — Move-semantics bugs**
   Use-after-move, missing `noexcept` on move ctor, self-move.

5. **`ITER` — Iterator invalidation**
   Mutate-while-iterating, `erase` without the returned next iterator.

6. **`LAMBDA` — Lambda capture bugs**
   Capture-by-reference outliving scope, capturing `this` into a handler stored longer than the object.

7. **`EXCEPT` — Exception safety**
   Leaks on throw, basic/strong/nothrow guarantee violations, throwing from dtors.

---

## Deconfliction

1. `MOVE` > `SPTR` (if the bug is use-after-move of a smart pointer, file `MOVE`).
2. `LAMBDA` > `MOVE` (if the capture is what outlives the object, file `LAMBDA`).
3. `EXCEPT` is the fallback when resource leakage occurs on a throw path and no more specific pass fits.
