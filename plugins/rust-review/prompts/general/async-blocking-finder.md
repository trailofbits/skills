---
name: async-blocking-finder
description: Detects std::sync, std::fs, std::thread::sleep, or other blocking std calls inside async functions
---

**Finding ID Prefix:** `ASYNCBLOCK`.

**Gates:**

1. Inside `async fn` or `async {}` block.
2. Blocking call: `std::sync::{Mutex,RwLock}::lock`, `std::fs::*`, `std::thread::sleep`, `std::net::*`, blocking channel.
3. Not already offloaded via `tokio::task::spawn_blocking` / `block_in_place`. **Caveats:** `block_in_place` requires the multi-thread runtime (it *panics* on a `current_thread` runtime), so a `block_in_place` wrapper is not a universal clear; and **neither** wrapper resolves the `std::sync::Mutex`/`RwLock` guard held *across* an `.await` (the guard is `!Send` and its lifetime spanning the await is the defect — the synchronous closure passed to `spawn_blocking`/`block_in_place` cannot span an await).

**Patch:** switch to `tokio::sync` / `tokio::fs` / `tokio::time::sleep`, or offload genuinely-blocking CPU/IO work via `spawn_blocking` (use `block_in_place` only on the multi-thread runtime). For a lock guard held across `.await`, use `tokio::sync::Mutex` or drop the guard before the await — wrapping in `spawn_blocking`/`block_in_place` cannot fix that case.
