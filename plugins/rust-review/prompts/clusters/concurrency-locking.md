---
name: cluster-concurrency-locking
kind: cluster
consolidated: true
covers:
  - double-lock-deadlock # DLOCK
  - abba-deadlock        # ABBA
  - condvar-misuse       # CONDVAR
  - channel-starvation   # CHANSTARVE
  - once-reentrancy      # ONCEREENTRY
  - reentrancy-unsafe    # REENTRANT
---

# Cluster: Concurrency — locking & blocking

Per empirical study, 30/38 Rust deadlocks are **double-lock** caused by `MutexGuard` lexical scope misunderstanding. ABBA, condvar, channel starvation, and `Once` reentrancy round out the blocking-bug surface.

ID prefixes: `DLOCK`, `ABBA`, `CONDVAR`, `CHANSTARVE`, `ONCEREENTRY`, `REENTRANT`.

---

## Phase A — Build the lock map (ONCE)

```
rg seed: "\b(Mutex|RwLock|parking_lot::(Mutex|RwLock))::new\b"
rg seed: "\.(lock|read|write|try_lock|try_read|try_write)\s*\("
rg seed: "\bCondvar\b"
rg seed: "\b(mpsc::(channel|sync_channel)|crossbeam_channel::(bounded|unbounded)|tokio::sync::(mpsc|oneshot|broadcast))\b"
rg seed: "\.(call_once|get_or_init)\s*\(|\b(Once::call_once|OnceCell::get_or_init|OnceLock::get_or_init|LazyLock::(new|force)|Lazy::(new|force))\b"  # dominant method form `INIT.call_once(`/`CELL.get_or_init(` + type-qualified forms
rg seed: "\bsigaction\b|\bsignal_hook\b|\blibc::signal\b|nix::sys::signal"
```

For each lock acquisition, record `lock_map[site] = { mutex_var, guard_name_if_bound, lexical_scope_end }`. If the lock result is unbound and used as a temporary in a `match` / `if let` / `while let` **scrutinee** (e.g. `if let Some(v) = m.lock().unwrap().get(k) { … }`), the guard lives until the **end of that whole expression's block** — the classic footgun. Note this explicitly. (A plain `if m.lock().unwrap().is_empty() { … }` whose condition is a bare `bool` is different: that temporary drops at the end of the *condition*, before the body — so the prolonged-hold concern applies to scrutinee temporaries, not every unbound lock.)

---

## Phase B — Run passes in order

### 1. `DLOCK` — Double-lock via guard lexical scope

For each lock acquisition `g = m.lock()`: find every subsequent lock on the same `m` (via `rg` + flow analysis) within `g`'s lexical scope. If any exists on a reachable path, file `DLOCK`.

Especially scrutinize:
- `if let Some(x) = m.lock().unwrap().get(k) { /* temporary holds m */ }`
- `match m.read() { ... }` — guard lives until end of `match` arm.
- Reentrant function calls (where the function itself takes `m`).

### 2. `ABBA` — Conflicting lock ordering

Build a directed graph `G` where edge `(A, B)` means some function acquires A then B without releasing A. Detect cycles. Any cycle is a potential ABBA deadlock.

### 3. `CONDVAR` — Wait without reachable notifier

For each `Condvar::wait(_while|_timeout)?`: confirm at least one `notify_one`/`notify_all` is reachable on a different thread, **and that the predicate the waiter checks is mutated while holding the companion `Mutex`**. The real lost-wakeup condition is a predicate write that is *not* protected by the lock — do **not** require the notifier to still hold the lock during the `notify` call: mutate-under-lock → drop the guard → `notify` is the std-documented correct pattern (the notifier need not hold the lock across `notify`), so flagging it would be a false positive.

### 4. `CHANSTARVE` — Orphaned channel endpoints

For each `Receiver::recv()` blocking call: confirm at least one `Sender` clone reaches a corresponding `send` on a different thread. Symmetrically for bounded `Sender::send` on a full channel.

### 5. `ONCEREENTRY` — Recursive `call_once`

The closure passed to `Once::call_once` / `OnceCell::get_or_init` / `OnceLock::get_or_init` MUST NOT call back into the same cell. For `LazyLock` (and `once_cell`'s `Lazy`) the initializer is the closure passed to `LazyLock::new(...)`, re-entered when its own value is read via `*L` / `Deref` / `LazyLock::force(&L)` inside that initializer — note `LazyLock` exposes **no** `call_once`/`get_or_init`, so detect its reentrancy by an init closure that references the same `LazyLock` static. Trace the closure body for direct or transitive recursion.

### 6. `REENTRANT` — Non-reentrant code reachable from a signal handler

The set of operations safe to call from a POSIX signal handler is small (the "async-signal-safe" set per `signal-safety(7)`): no `malloc`/`free`, no `Mutex::lock`, no `printf`/`println!`, no allocation, no Rust panics. Rust's `std::sync::Mutex` is not reentrant; calling `lock()` twice on the same mutex from the same thread is **unspecified** per the std contract — it deadlocks or panics, but never returns (already covered by `DLOCK` for lexical cases — this pass catches the *signal-handler* case).

For each handler registered via `libc::signal`, `libc::sigaction`, `signal_hook`, or `nix::sys::signal::sigaction` as an `extern "C" fn` (the actual signal-handler body). Note `tokio::signal` does **not** belong here — users never register an `extern "C" fn` with it; it installs its own handler and delivers signals via an async `Signal` stream in a normal task (see the FP list below):

1. Trace the function body and every call it makes (one level deep is sufficient for most signal handlers — they are short).
2. Flag any call to: an allocator (`Box::new`, `Vec::push` if the vec may grow, `String::push_str`, `format!`, `to_string`), a lock (`.lock()`, `.read()`, `.write()`), stdio (`println!`, `eprintln!`, `print!`), `panic!`/`unwrap`/`expect`, or any other non-async-signal-safe std function.
3. Also flag reentrant patterns *outside* signal handlers: a function `f` that takes `&Mutex<T>` and calls back into user code (closures, dyn traits) which may re-enter `f` on the same `Mutex` — separate from `DLOCK` because the recursion is through dynamic dispatch, not lexical scope.

**FPs to reject:**

- Signal handler that only writes to an `AtomicBool`/`AtomicUsize` flag and reads from an `extern "C"` (no allocs, no locks, no formatting).
- `tokio::signal::ctrl_c` and similar async-runtime-mediated signal facilities (the handler runs in a normal task, not the signal-handler context).
- Functions exposed as signal handlers but documented `unsafe fn` whose `/// # Safety` block lists the async-signal-safe operations only.

**Patch:** restrict the signal-handler body to writing an `AtomicBool` flag and have the main thread observe and react. For reentrant-lock patterns outside signal handlers, document the invariant that the callback must not re-enter, or switch to a reentrant lock primitive (`parking_lot::ReentrantMutex`, whose guard yields only `&T` — reentrant *mutation* additionally needs a `Cell`/`RefCell` inside it) with explicit rationale.

---

## Deconfliction

Report only one finding per `(path, line)`. `DLOCK` and `ABBA` are distinct (single-mutex vs multi-mutex). `CONDVAR` and `CHANSTARVE` are independent. `ONCEREENTRY` is independent.

`REENTRANT` is independent of `DLOCK`: lexical double-lock is `DLOCK`, signal-handler-or-callback re-entry is `REENTRANT`. Report both when both apply.

Build `lock_map` ONCE.
