---
name: packed-field-ref-finder
description: Detects undefined behavior from creating references to fields of #[repr(packed)] structs, including implicit borrows via auto-deref
---

**Finding ID Prefix:** `PACKEDREF`.

**Bug shape:** `#[repr(packed)]` / `#[repr(C, packed)]` / `#[repr(packed(N))]` removes inter-field padding, so fields with alignment > 1 can sit at unaligned addresses. Rust requires every `&T` / `&mut T` to be aligned *at creation*, not only on dereference. Taking `&s.field`, `&mut s.field`, `&s.field as *const _`, or any context that implicitly borrows the field (`println!("{}", s.field)`, `&self` method calls on the field, `match &s.field`, indexing a nested array field) is UB when the field is misaligned. Common in C-FFI layout-matched structs and wire formats. Modern rustc rejects most sites as `E0793`, but legacy code, `#[allow(unaligned_references)]`, and macro-generated borrows still appear.

**Verification gates (ALL must pass):**

1. **Packed struct in scope:** a type annotated `#[repr(packed)]`, `#[repr(C, packed)]`, or `#[repr(packed(N))]` (including via type alias or generic instantiation).
2. **Reference or implicit borrow of a field:** explicit `&s.field` / `&mut s.field`; `&s.field as *const _` / `&mut s.field as *mut _` (the `&` still forms an unaligned reference before the cast); or an auto-borrow site such as `println!`/`format!`/`Debug` on a non-`Copy` field, passing `s.field` where a reference is expected, or indexing/splitting a nested array field.
3. **Field may be misaligned:** the field type has `align_of > 1` (skip `u8`/`i8`/`bool` and `[u8; N]`). For `#[repr(packed(N))]` with `N > 1`, skip fields whose type alignment is `<= N` only when a `// SAFETY:` comment proves both the struct base address and field offset meet that alignment; otherwise flag for reviewer confirmation.
4. **Not a by-value copy:** the access is not `{ s.field }`, `let v = s.field`, or an assignment/move that copies by value without forming a reference.

**FPs to reject:**

- Direct by-value read/write of a `Copy` field (`let x = s.field; s.field = v;`), including braced copies in macros (`println!("{}", { s.field })`).
- `ptr::addr_of!(s.field)` / `ptr::addr_of_mut!(s.field)` plus `read_unaligned` / `write_unaligned` / `copy_nonoverlapping` — no intermediate `&T` is formed.
- Raw borrow syntax `&raw const s.field` / `&raw mut s.field` (no reference invariants).
- Field type has alignment 1, or the leaf field nested in the packed struct is alignment 1.
- Test-only `#[cfg(test)]` modules.

**Search patterns:**

```
#\[repr\([^\]]*packed
\b&(?:mut\s+)?[\w.]+\.\w+
\b(?:println|format|write|writeln)!\([^)]*\.\w+
```

For each `repr(packed*` hit, grep the struct name for field-borrow sites and check the gates per site.

**Patch:** read/write `Copy` fields by value; otherwise use `ptr::addr_of!` / `ptr::addr_of_mut!` with `read_unaligned` / `write_unaligned`, preferring `&raw const` / `&raw mut` over `&field as *const _`. If alignment can be restored, drop `packed` or add explicit padding fields.

Distinct from `REPRC` (field reordering from a missing `repr` at an FFI boundary) and `REPRCPAD` (uninitialized padding leaking across FFI), and from `PTRCAST` (pointer provenance / cast-to-wrong-type UB — distinct from forming an unaligned `&T`).
