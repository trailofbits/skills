---
name: cancel-safety-finder
description: Detects await points across mutable state mutation that can corrupt on cancellation (select! drop)
---

**Finding ID Prefix:** `CANCELSAFETY`.

**Bug shape:** future does `state.partial_write(); some_async().await; state.commit();` — if the future is cancelled at the `.await`, `state` is left half-written.

**Gates:**

1. Async function with state mutation BEFORE an `.await` AND a corresponding completion mutation AFTER.
2. The future is used inside `tokio::select!` / `futures::select!` (where cancellation is the norm) OR documented as cancellable.
3. No `scopeguard` / `Drop` impl restores invariants on cancellation.

**Patch:** restructure so the mutation is atomic across `.await` (do it entirely before the await, or after with no intervening await), restore invariants via a `Drop`/`scopeguard` guard on cancellation, or run the mutation in a `tokio::spawn`ed task so it completes **detached** from the `select!` (losing the select branch drops the `JoinHandle`, not the running task). Note a spawned task is **not** literally non-cancellable — it is still abortable via `JoinHandle::abort`; the benefit is detaching the mutation from the cancelled `select!` branch.
