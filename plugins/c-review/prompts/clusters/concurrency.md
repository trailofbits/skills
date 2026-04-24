---
name: cluster-concurrency
kind: cluster
consolidated: false
covers:
  - race-condition         # RACE
  - thread-safety          # THREAD
  - spinlock-init          # SPINLOCK
  - signal-handler         # SIGNAL
---

# Cluster: Concurrency

Four bug classes sharing one expensive piece of shared context: **the project's locking / atomic / signal model**. Build that model once; then each pass asks a specific question of it.

ID prefixes: `RACE`, `THREAD`, `SPINLOCK`, `SIGNAL`.

---

## Phase A — Build the concurrency model (ONCE per run)

Identify, in this order:

```
Grep: pattern="(?i)\\b(pthread_mutex|pthread_rwlock|pthread_spin|pthread_cond|pthread_create|pthread_join|pthread_once)"
Grep: pattern="\\b(atomic_|__atomic_|__sync_|FD_ATOMIC|fd_rwlock)"
Grep: pattern="\\b(sigaction|signal|sigprocmask|pthread_sigmask|sigwait)\\s*\\("
Grep: pattern="\\b(volatile)\\b.*\\*"
Grep: pattern="\\b(tls|thread_local|__thread|_Thread_local)\\b"
```

For each mutex/rwlock/spinlock/atomic primitive you find, record:
- The variable or member it guards (usually `foo_lock` → guards the `foo_*` fields).
- Its init site.
- Its destroy/free site.
- Its acquire and release sites.

For each signal handler, record:
- The signals it handles.
- Whether it calls any non async-signal-safe function (use the POSIX list).

This is `lock_model`. Do not file findings during Phase A.

---

## Phase B — Passes in order (reuse `lock_model`)

1. **`SPINLOCK` — Uninitialized spinlock / lock primitive**
   Cheap check — any acquire site whose primitive has no matching init site.

2. **`THREAD` — Thread-safety**
   Flags unsafe libc functions (`strtok`, `rand`, `localtime`, `readdir`, …) called from threaded code.

3. **`RACE` — Race conditions**
   Uses `lock_model` to flag: guarded-field access without the guard held; lock/unlock imbalance; TOCTOU; read→write→read lock cycles that invalidate previously-held pointers.

4. **`SIGNAL` — Signal-handler safety**
   For each handler in `lock_model`, verify async-signal-safety of every callee (transitively).

---

## Deconfliction

Priority (higher wins):

1. `RACE` > `THREAD` (if the thread-safety issue is specifically about a missing lock, file `RACE`).
2. `SIGNAL` is independent.
3. `SPINLOCK` is independent — it's about init state, not ordering.

---

## Token-economy reminder

The lock_model is the expensive part — do not rebuild it per pass. Write it as a compact table in your working notes and reference it.
