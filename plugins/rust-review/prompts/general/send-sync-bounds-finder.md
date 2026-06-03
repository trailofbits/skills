---
name: send-sync-bounds-finder
description: Detects generic APIs missing Send/Sync bounds when crossing threads
---

**Finding ID Prefix:** `SENDSYNCBOUND`.

**Bug shape:** `fn spawn<F: FnOnce()>(f: F)` — missing `+ Send + 'static` lets non-Send closures cross threads via this API.

**Gates:**

1. Function spawns threads (`std::thread::spawn`, `tokio::spawn`, `rayon::spawn`) OR sends values across channels.
2. Generic parameter for the spawned closure/value lacks `+ Send` (and `+ 'static` for `std::thread::spawn`).

**FPs:**

- Thread-local executor where Send is unnecessary (`tokio::task::spawn_local`).
- Inner trait bound already implies Send (e.g., `T: Future<Output: Send> + Send`).

**Search:**

```
\bspawn\s*[(<]
FnOnce|FnMut|Fn\b
where|:\s*Send
```
