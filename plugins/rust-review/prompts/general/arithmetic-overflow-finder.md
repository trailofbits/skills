---
name: arithmetic-overflow-finder
description: Detects unchecked arithmetic on untrusted integers that panics in debug and silently wraps in release (or panics under overflow-checks=true)
---

**Finding ID Prefix:** `ARITHOFL`.

**Gates:**

1. Arithmetic operator (`+`, `-`, `*`, `<<`, `>>`, unary `-`) on an integer derived from external input.
2. No `checked_*`, `saturating_*`, `wrapping_*`, or `overflowing_*` wrapper.
3. Either: (a) the crate uses `overflow-checks = true` in release (`Cargo.toml`), making this a DoS, OR (b) it doesn't, making this silent corruption (still report — different severity).

**Casts:** `as` between integer widths that can truncate is in scope (e.g., `u64 as u32` when value can exceed `u32::MAX`).

**FPs:**

- Both operands are statically bounded constants.
- Code explicitly handles the overflow case after an `overflowing_*` check.
- `usize` arithmetic on `.len()` results where the array length is bounded by allocation limit.

**Patch:** use `checked_*` and propagate `None`/error, or `saturating_*` if clamping is semantic, or document `wrapping_*` as intentional.
