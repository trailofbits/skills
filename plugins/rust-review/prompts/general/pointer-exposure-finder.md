---
name: pointer-exposure-finder
description: Detects raw memory addresses leaked to externally observable sinks, defeating ASLR
---

**Finding ID Prefix:** `PTREXPOSE`.

**Bug shape:** A runtime memory address derived from `ptr as usize`, `{:p}` formatting, `.addr()`, or a pointer-to-integer transmute reaches an externally observable sink (log shipped off-host, HTTP response, serialized output, error string returned to a remote party). The leaked address defeats ASLR and supplies layout information to exploit any co-present memory-corruption bug.

**Gates:**

1. An address value is derived from a pointer, reference, or `Box`/`Arc`/`Rc` via cast, `{:p}`, `.addr()`, or transmute.
2. The value reaches a sink observable by an external or unprivileged party: log shipped off-host, API response, serialized data, or error message returned over a channel.

**FPs:**

- Output guarded by `#[cfg(debug_assertions)]` or `cfg!(debug)` — never reaches production.
- Value never leaves the process (internal data-structure key, purely in-process logging).
- Address used only as an opaque integer key, never sent outside the process boundary.

**Patch:** do not expose raw addresses externally; assign stable opaque identifiers or use a hash of a stable key if a handle is needed.
