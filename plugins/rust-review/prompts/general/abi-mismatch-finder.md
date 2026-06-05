---
name: abi-mismatch-finder
description: Detects extern "C" function signatures that disagree with the C header in arg type, count, or return type
---

**Finding ID Prefix:** `ABIMISMATCH`.

**Gates:**

1. `extern "C" { fn foo(...) -> ...; }` declaration.
2. The C header (located via `bindgen` build script, vendored `.h`, or comment reference) shows different types/arity.
3. Mismatch is not a documented Rust-side opaque wrapper.

**FPs:**

- `c_int` vs `i32` — same on common targets.
- `*mut T` vs `*mut c_void` where T is the underlying type (handle pattern).
- Use of `#[link]` against a different lib version is OOS for this finder.

**Patch:** regenerate via `bindgen`; pin C header version.
