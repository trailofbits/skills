---
name: static-mut-race-finder
description: Detects unsynchronized reads/writes to static mut shared across threads (data race + UB)
---

**Finding ID Prefix:** `STATICMUT`.

**Bug shape:** `static mut` is a single process-wide alias with no borrow-checker protection, so any concurrent read/write without a `Mutex`/`RwLock`/`Atomic*`/`Once` (or other documented happens-before) is a data race and immediate UB. This includes raw-pointer access via `&raw mut` / `addr_of_mut!` / `ptr::read` / `ptr::write` that never forms a reference. Rust 2024's `static_mut_refs` lint (`deny` by default) only blocks `&FOO` / `&mut FOO` (including autoref from method calls); it does not make raw or direct `unsafe` access sound.

**Verification gates (ALL must pass):**

1. **`static mut` site:** `static mut <NAME>: <T> = ...` in scope (including inside nested items).
2. **Read or write access:** direct assignment/read in `unsafe`, `*(&raw mut NAME)`, `addr_of_mut!(NAME)` + deref, or `ptr::read`/`ptr::write`/`copy` targeting the static's address. Do not require a `&T`/`&mut T` — those are usually `static_mut_refs` violations in 2024.
3. **No synchronization on the access path:** not mediated by `Atomic*::{load,store,fetch_*}` with documented orderings; not behind `Mutex`/`RwLock`/`spin::Mutex` on an **immutable** static; not gated by `Once` / `OnceLock::get_or_init` so all mutating paths happen-before publication; no `// SAFETY:` naming an external happens-before.
4. **Concurrent reachability:** at least one other context can touch the same static without ordering — `thread::spawn`, `tokio::spawn` / runtime workers, `rayon`, thread pools, `#[no_mangle]` / `extern "C"` callbacks from other threads, or signal handlers.

**FPs to reject:**

- `static mut` is only written during `main` before any thread/task spawns and never touched afterward (prove from call graph).
- All post-init access goes through an **immutable** static wrapping `Mutex`/`Atomic*`/`OnceLock` (the `static mut` is dead code — suggest deleting, do not file).
- Access is confined to one OS thread by API contract **and** a `// SAFETY:` names the invariant.
- `#[allow(static_mut_refs)]` with a `// SAFETY:` documenting real synchronization; still file if it does not explain happens-before against every other accessor.

**Search patterns:**

```
\bstatic\s+mut\b
&raw\s+(const|mut)\s+|addr_of_mut!
ptr::(read|write|copy|swap)(_nonoverlapping)?
\b(Atomic\w+|Mutex|RwLock|OnceLock|LazyLock|Once)\b
thread::spawn|tokio::spawn|rayon::spawn|extern\s+"C"
```

For each `static mut` hit, enumerate all access sites and check gates.

**Patch:** replace `static mut` with an immutable `static NAME: AtomicT` / `Mutex<T>` / `OnceLock<T>` (use `fetch_add` for counters). If low-level access is required, use `&raw mut` only while holding a lock, with a `// SAFETY:` naming the lock and every concurrent accessor.
