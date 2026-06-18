---
name: send-sync-bounds-finder
description: Detects generic APIs missing Send/Sync bounds when crossing threads
---

**Finding ID Prefix:** `SENDSYNCBOUND`.

**Bug shape:** a non-`Send` (or non-`'static`) value/closure crosses a thread boundary **without** the bound being enforced — but **not** via a direct `std::thread::spawn`/`tokio::spawn`/`rayon::spawn`, which already require `F: Send + 'static` (a wrapper that "forgets" the bound simply fails to compile — a non-bug). The genuinely unsound shapes launder the bound through `unsafe`: a raw `thread::Builder` + `mem::transmute` of the closure/lifetime, an FFI/custom thread-spawn, `std::thread::scope` misuse, or storing the value into a `Send`/`Sync` container or sending it past a **manual `unsafe impl Send`/`Sync`**.

**Gates:**

1. A value/closure reaches a thread/channel boundary through an `unsafe` spawn primitive (raw `thread::Builder` + `transmute`, FFI thread create, scoped-thread misuse) **or** is laundered across threads by a manual `unsafe impl Send`/`Sync` or a `Send`/`Sync` container.
2. The missing `Send`/`Sync` bound is genuinely **not** enforced by the sink — the code compiles *only because* an `unsafe` construct bypasses it. A direct `std::thread::spawn`/`tokio::spawn`/`rayon::spawn` cannot itself be the unsoundness: it enforces `Send + 'static`, so anything that compiles around it already carries the bound.

**FPs:**

- A wrapper around a bare `std::thread::spawn`/`tokio::spawn`/`rayon::spawn` that omits an explicit `Send` bound — it cannot compile unless the bound already holds, so there is no bug.
- Thread-local executor where Send is unnecessary (`tokio::task::spawn_local`).
- Inner trait bound already implies Send (e.g., `T: Future<Output: Send> + Send`).

**Search:**

```
\bspawn\s*[(<]
FnOnce|FnMut|Fn\b
where|:\s*Send
unsafe\s+impl\b.*\b(Send|Sync)\b|thread::Builder|\btransmute\b|thread::scope
```

**Patch:** propagate the bound (`+ Send + 'static`) on the wrapper, or replace the `unsafe` spawn / `unsafe impl` with a sound primitive; if a manual `unsafe impl Send`/`Sync` is intended, document the synchronization invariant that justifies overriding the auto-derived `!Send`/`!Sync`.
