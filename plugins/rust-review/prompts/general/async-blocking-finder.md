---
name: async-blocking-finder
description: Detects std::sync, std::fs, std::thread::sleep, or other blocking std calls inside async functions
---

**Finding ID Prefix:** `ASYNCBLOCK`.

**Gates:**

1. Inside `async fn` or `async {}` block.
2. Blocking call: `std::sync::{Mutex,RwLock}::lock`, `std::fs::*`, `std::thread::sleep`, `std::net::*`, blocking channel.
3. Not wrapped in `tokio::task::spawn_blocking` / `block_in_place`.

**Patch:** switch to `tokio::sync` / `tokio::fs` / `tokio::time::sleep`, OR wrap in `spawn_blocking`.
