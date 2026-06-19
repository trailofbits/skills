---
name: arithmetic-overflow-finder
description: Detects unchecked arithmetic on untrusted integers that panics in debug and silently wraps in release (or panics under overflow-checks=true)
---

**Finding ID Prefix:** `ARITHOFL`.

**Gates:**

1. Arithmetic operator (`+`, `-`, `*`, `<<`, `>>`, unary `-`) on an integer derived from external input.
2. No `checked_*`, `saturating_*`, `wrapping_*`, or `overflowing_*` wrapper. **This exclusion scopes the overflow/truncation cases in gates 1 & 3 only — it does NOT clear the unconditional divide-by-zero / `i::MIN / -1` panics in gate 4.** `wrapping_div`/`saturating_div`/`overflowing_div` and the `_rem` forms still panic on a zero divisor, so a `wrapping_*`/`saturating_*`/`overflowing_*` wrapper does **not** suppress a gate-4 finding; only `checked_div`/`checked_rem` do.
3. Either: (a) the crate uses `overflow-checks = true` in release (`Cargo.toml`), making this a DoS, OR (b) it doesn't, making this silent corruption (still report — different severity).
4. **Unconditional-panic arithmetic (independent of `overflow-checks`):** `/` or `%` whose divisor is derived from external input and can be zero, and `i::MIN / -1` / `i::MIN % -1` (signed division overflow). These panic in **every** profile — debug *and* release — regardless of `overflow-checks`, so file them whenever the divisor/operand is attacker-reachable and not provably non-zero / non-`MIN`. Note `wrapping_div`/`saturating_div`/`overflowing_div` (and the `_rem` forms) **still panic on divide-by-zero**; only `checked_div`/`checked_rem` are safe. (This mirrors the `panic-dos` cluster Phase A, which routes these unconditional panics here under `ARITHOFL`.)

**Casts:** `as` between integer widths that can truncate is in scope (e.g., `u64 as u32` when value can exceed `u32::MAX`).

**FPs:**

- Both operands are statically bounded constants.
- Code explicitly handles the overflow case after an `overflowing_*` check.
- `usize` arithmetic on `.len()` results where the array length is bounded by allocation limit.

**Patch:** use `checked_*` and propagate `None`/error, or `saturating_*` if clamping is semantic, or document `wrapping_*` as intentional.
