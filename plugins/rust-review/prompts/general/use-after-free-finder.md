---
name: use-after-free-finder
description: Detects use-after-free via raw pointers escaping implicit Drop scope in Rust
---

**Finding ID Prefix:** `UAF` (e.g., UAF-001).

**Bug shape (from research):** 11/14 production UAF bugs follow this pattern — a complex object is created in a lexical scope, a raw pointer is extracted via `.as_ptr()` / `.as_mut_ptr()`, the original object is implicitly Dropped at end-of-scope (especially temporaries in `match` arms or `if let` bindings), and the raw pointer is dereferenced afterward.

**Verification gates (ALL must pass):**

1. **Extraction:** raw pointer obtained via `.as_ptr()`, `.as_mut_ptr()`, `Box::into_raw`, or transmute.
2. **Termination:** source object goes out of scope OR is reassigned, triggering `Drop`.
3. **Dereference:** the raw pointer is dereferenced (read, write, offset, copy_*) chronologically AFTER the Drop in (2).
4. **Mitigation absence:** no `mem::forget`, `ManuallyDrop`, or `Box::leak` neutralized the Drop.

If any gate fails, do not file.

**Common false positives to avoid:**

- Pointer extracted but `let _binding = source;` extends source's scope past pointer use.
- Source object is `'static` (no Drop).
- `Pin<&'a mut T>` where lifetime tracking is sound.
- Pointer comes from `Box::leak()` — explicit lifetime extension to `'static`.

**Search patterns:**

```
\.(as_ptr|as_mut_ptr)\(
\b(Box|CString)::into_raw\b|Vec::into_raw_parts|\btransmute\b
ptr::(read|write|copy(_nonoverlapping)?)
\.(offset|add|sub|read|write)\s*\(
let\s+\w+\s*=\s*[^;]+\.as_ptr\(\)
```

Notes: `offset`/`add`/`sub` and `read`/`write` are **methods** on raw pointers (`p.add(i)`, `p.read()`), not `ptr::` free functions — `ptr::offset` / `ptr::add` do not exist, so the dereference is seeded by the method-form line, not the `ptr::` line. The `into_raw` / `into_raw_parts` / `transmute` line seeds the extraction sources named in Gate 1 that `.as_ptr()` alone misses.

**Patch recommendation to suggest:** bind the source to a longer-lived variable, or use `Box::leak` / `mem::forget` explicitly when intentional, or replace the raw pointer with a `&T` whose lifetime the borrow-checker can verify.
