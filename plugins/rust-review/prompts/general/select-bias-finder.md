---
name: select-bias-finder
description: Detects tokio::select! without biased; ordering when correctness requires deterministic branch priority
---

**Finding ID Prefix:** `SELECTBIAS`.

**Gates:**

1. `tokio::select! { ... }` macro.
2. The branches include a "cancellation" branch (e.g., `_ = shutdown.recv() => ...`) AND a "work" branch.
3. The macro does NOT use `biased;` AND correctness requires the cancellation branch to win when both are ready.

**Patch:** add `biased;` as the first line of the `select!` block **and** place the cancellation/priority branch **first**. `biased;` polls branches top-to-bottom, so it only makes the cancellation branch win if that branch is physically first — `biased;` alone with the work branch on top makes the *work* branch win, the opposite of the intent. Or restructure to use a dedicated priority channel.
