---
name: bufwriter-unflushed-finder
description: Detects BufWriter (and other buffered writers) dropped without an explicit flush, silently swallowing write errors
---

**Finding ID Prefix:** `BUFFLUSH`.

**Bug shape:** A `BufWriter` (or other buffered writer) is dropped without an explicit `flush()`. The implicit flush in `Drop` ignores its error, so write failures (disk full, broken pipe) are silently swallowed and buffered data may be lost — corrupting output or hiding a failure the caller needed to see.

**Gates:**

1. A `BufWriter` (or buffered writer) goes out of scope (dropped) without an explicit `flush()` or `into_inner()`.
2. Write success matters (persisted file, protocol output, integrity-relevant data).

**FPs:**

- Explicit `flush()` (or `into_inner()`) with the error handled before drop.
- Output is best-effort/cosmetic with no correctness requirement.

**Patch:** call `flush()` (or `into_inner()`) explicitly and propagate the error before the writer is dropped.
