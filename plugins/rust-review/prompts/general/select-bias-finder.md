---
name: select-bias-finder
description: Detects tokio::select! without biased; ordering when correctness requires deterministic branch priority
---

**Finding ID Prefix:** `SELECTBIAS`.

**Gates:**

1. `tokio::select! { ... }` macro.
2. The branches include a "cancellation" branch (e.g., `_ = shutdown.recv() => ...`) AND a "work" branch.
3. The macro does NOT use `biased;` AND correctness requires the cancellation branch to win when both are ready.

**Patch:** add `biased;` as the first line of the `select!` block, OR restructure to use a dedicated channel.
