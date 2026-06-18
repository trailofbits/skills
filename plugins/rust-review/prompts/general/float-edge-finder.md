---
name: float-edge-finder
description: Detects NaN/Inf/subnormal handling gaps in float arithmetic on security-relevant paths
---

**Finding ID Prefix:** `FLOATEDGE`.

**Gates:**

1. `f32`/`f64` arithmetic on input data.
2. Result is used as: a length, an index (via `as usize`), a comparison driving authorization, a serialization size.
3. No `is_finite()` / `is_nan()` guard.

**Why:** `NaN != NaN`; ordering with NaN breaks `partial_cmp`; `f64 as usize` on Inf/NaN is a **fully-defined saturating cast** since Rust 1.45 (NaN→0, +Inf→`usize::MAX`, negatives→0) — not UB and not implementation-defined. The hazard is the silent saturation: an unchecked NaN/Inf becomes `0` or `usize::MAX` and is then used as a length/index/size (a zero-length buffer, or an allocation of `usize::MAX`).
