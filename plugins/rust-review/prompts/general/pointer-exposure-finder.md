---
name: pointer-exposure-finder
description: Detects raw memory addresses leaked to externally observable sinks, defeating ASLR
---

**Finding ID Prefix:** `PTREXPOSE`.

**Bug shape:** A runtime memory address derived from `ptr as usize`, `{:p}` formatting, or `.addr()` / `.expose_provenance()` reaches an externally observable sink (log shipped off-host, HTTP response, serialized output, error string returned to a remote party). The leaked address defeats ASLR and supplies layout information to exploit any co-present memory-corruption bug.

**Gates:**

1. An address value is derived from a pointer, reference, or `Box`/`Arc`/`Rc` via cast, `{:p}`, or `.addr()` / `.expose_provenance()` (the stable-since-1.84 exposing form; older `.expose_addr()`). (A pointer laundered to an integer via `transmute` is surfaced by the `TRANS`/`PTRCAST` pass in unsafe-boundary; this pass keys on the cast / format / `addr` forms that the info-disclosure Phase-A grep seeds.)
2. The value reaches a sink observable by an external or unprivileged party: log shipped off-host, API response, serialized data, or error message returned over a channel.

**FPs:**

- Output guarded by `#[cfg(debug_assertions)]` / `cfg!(debug_assertions)` — compiled out of release builds. (Note: `cfg!(debug)` / `#[cfg(debug)]` is **not** a real guard — `debug` is not a built-in cfg name; it is `false` in normal dev builds and triggers the `unexpected_cfgs` warning. The correct flag is `debug_assertions`. Caveat: `[profile.release] debug-assertions = true` re-enables it in release.)
- Value never leaves the process (internal data-structure key, purely in-process logging).
- Address used only as an opaque integer key, never sent outside the process boundary.

**Patch:** do not expose raw addresses externally; assign stable opaque identifiers or use a hash of a stable key if a handle is needed.
