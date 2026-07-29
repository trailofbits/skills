---
name: resource-exhaustion-finder
description: Detects CPU or memory exhaustion DoS on untrusted size/count — unbounded loops, O(n²) amplification, uncapped allocation, unbounded channels
---

**Finding ID Prefix:** `RESEXHAUST`.

**Bug shape:** availability loss (CPU burn or RAM/OOM), not a panic abort, when attacker-controlled `n` drives unbounded iteration, O(n²) amplification (grow-a-vec then scan-per-element), uncapped allocation, or unbounded channel growth.

**Gates:**

1. A trust boundary feeds a size, count, length, record list, or iteration budget `n` from external input (packet, HTTP body, file, IPC, peer frame).
2. The handler does at least one: unbounded `loop`/`for`/`while` whose trip count is driven only by `n` with no `min(n, MAX)`/`take(MAX)`/budget break; superlinear work where nested loops or repeated scans both scale with `n`; uncapped allocation (`with_capacity`/`reserve`/`resize`, `vec![x; n]`, `repeat(n)`) on unclamped `n`; or unbounded buffering (`unbounded_channel`/`unbounded`, or a bounded channel with no backpressure on the untrusted path).
3. No reachable defense enforces a global budget before the expensive work (per-message cap, max body size *and* element count, `take(limit)`, constant `MAX_*` clamp, timeout with cancellation).

**Search patterns:**

```
(Vec|String|BytesMut|VecDeque)::(with_capacity|reserve)\s*\(|\.(reserve|reserve_exact|try_reserve|resize)\s*\(|vec!\[[^;]+;\s*\w+\]|repeat\s*\(
unbounded(_channel)?|async_channel::unbounded|crossbeam.*unbounded
for\s+\w+\s+in\s+0\.\.|while\s+.*\.len\(\)|loop\s*\{
```

Then trace whether the count is tainted from decode of external input.

**FPs:**

- `n` is a compile-time constant or from a fixed internal table.
- `n` is clamped with a small documented protocol max on **every** path before allocating/looping.
- Work is O(n) cheap **and** `n` is already capped by a stricter earlier size limit.
- Channel is unbounded but fed only by trusted internal tasks; untrusted path is bounded or uses `try_send` with drop/backpressure.

**Patch:** enforce protocol caps (max records/labels/bytes) before parse loops; never pass raw untrusted length to `with_capacity`/`reserve`, use `min(len, MAX)` or allocate incrementally; prefer bounded channels + `try_send`/backpressure; replace O(n²) structures with maps/sets.

**Deconfliction:** `RECURSEDES` is **stack** exhaustion from deep recursion, not CPU/RAM loop amplification. `ARITHOFL` is integer overflow on `+ - *`, not allocation/loop DoS.
