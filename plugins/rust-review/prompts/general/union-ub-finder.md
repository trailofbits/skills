---
name: union-ub-finder
description: Detects undefined behavior from union variant misreads and lifetime extension through union fields
---

**Finding ID Prefix:** `UNIONUB`.

**Bug shape:** Rust `union` types are bitwise overlays. Reading a field other than the most recently written one returns the bit pattern of the active variant *reinterpreted* as the read type — UB if the bits do not form a valid value of that type (e.g., reading a `&T` field after writing a `u64` produces a possibly-dangling reference). A secondary shape: taking a reference to one union field while another holds an owned value extends the owned value's lifetime in ways the borrow checker cannot reason about, producing aliasing UB.

**Verification gates (ALL must pass):**

1. **Union declared:** `union <Name> { ... }` in the scope. `#[repr(C)]` does **not** exempt a union — it fixes field *layout*, not field *validity*. Reading an inactive field whose type carries validity invariants (`&T`, `&mut T`, `NonNull`, `bool`, `char`, a niche-optimized enum) is UB regardless of `repr`, and `REPRC` (which only audits *struct* layout reprs) will never catch it. Let gate 4 below — the read field's type — be the discriminator; a `#[repr(C)]` union read only as `u8`/`[u8; N]`/`MaybeUninit` bytes is correctly cleared there and by the FP list.
2. **Read site inside `unsafe { }`:** field access `u.field` on a union value (Rust forces this inside `unsafe`).
3. **No matching write proof:** the most recent statement that fully assigns `u` (e.g., `u = U { other: ... }`, `u.field = ...`, `ptr::write(&raw mut u, ...)`) wrote a *different* field than the one now being read. Heuristic for grep-driven review without full dominator analysis: if the immediately preceding statement in the same block is not an assignment to the *same* field being read, OR the read is reached across a function boundary (the union is a struct field or function argument), flag the site and request reviewer confirmation rather than skipping.
4. **Read type has validity invariants:** the field type is a reference (`&T`, `&mut T`), `NonNull<T>`, `bool`, `char`, an enum with niche optimization, or a `#[repr(Rust)]` struct/enum. Skip if the read field is `u8`/`[u8; N]`/`MaybeUninit<T>` — any bit pattern is valid.

For the lifetime-extension variant: a `&u.a` or `&mut u.b` is taken while another field `u.c` holds an owned `Drop` value, and the reference is used (read/passed) past a point where `u` is reassigned or goes out of scope.

**FPs to reject:**

- Union accessed only through `MaybeUninit::write`/`assume_init` discipline equivalent to a tagged-union state machine documented in a `// SAFETY:` comment that names the active variant.
- C-FFI struct unions where only `u8`/`MaybeUninit` payloads are read.
- Test-only `#[cfg(test)]` modules.

**Search patterns:**

```
\bunion\s+\w+\b
```

This pre-filter has known false hits: `.union(`/`::union(` method calls (e.g., `HashSet::union`), and `union` used as a non-reserved identifier. Reject those at inspection time. Then for each *real* union declaration, grep its type name to find construction and field-access sites, and check gates per-site.

**Patch:** replace the union with an `enum` if the tag is statically known; or use `ManuallyDrop<T>` fields and document the active-variant invariant with a `// SAFETY:` comment naming the responsible writer at each read site; or, when the access truly is reinterpretation, use `MaybeUninit::<T>::assume_init` only after a proof that the bytes form a valid `T`.
