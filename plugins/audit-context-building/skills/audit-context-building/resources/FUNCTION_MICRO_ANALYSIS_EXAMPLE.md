# Worked Example

A complete per-function analysis. The subject is C; the format is language-neutral, and the notes at the end
cover what changes for contract code.

The point of this example is the callee. `session_acquire` looks safe read on its own, and the analysis only
becomes accurate once `session_lookup` has been read.

---

## `session_acquire` in src/session.c (L112-L138)

```c
// L112
int session_acquire(uint32_t id, struct session **out) {
    struct session *s = session_lookup(id);      // L113
    if (!s)                                       // L114
        return -ENOENT;
    s->refcount++;                                // L116
    *out = s;                                     // L117
    return 0;
}
```

**Purpose:** Hands a caller a borrowed reference to a live session and records that the borrow happened, so
the session is not freed underneath it. Every caller that later calls `session_release` is paired with this
function; the refcount discipline of the whole session table rests on that pairing.

**Inputs & Assumptions:**
- `id` (uint32_t): session identifier. Trust: **untrusted** — reaches this from the request parser at
  `src/proto.c:L88` without validation.
- `out` (struct session **): caller-provided storage for the result. Trust: trusted (internal callers only,
  per the caller list below).
- Implicit: the global session table `g_sessions` (`src/session.c:L31`) and the lock protecting it.
- Precondition: `out` is non-NULL. Nothing in this function establishes it and nothing checks it; both
  callers pass the address of a local (`src/proto.c:L94`, `src/admin.c:L51`).
- Precondition: the caller holds `g_session_lock`. Established by the callers, not here — see Open Questions.

**Outputs & Effects:**
- Returns `0` on success, `-ENOENT` when no session matches.
- State write: increments `s->refcount` (L116).
- State write: `*out` on the success path only. **On the error path `*out` is left untouched** (L114), so a
  caller that does not check the return value reads whatever was in its local.
- No external interactions, no events.
- Postcondition on success: the session's refcount is one higher and the caller owes a matching
  `session_release`.

**Block-by-Block:**

```c
// L113
struct session *s = session_lookup(id);
```
- **What:** Resolves the untrusted `id` to a session pointer.
- **Why here:** Nothing can proceed without the lookup, and it is the only place `id` is consumed.
- **Assumes:** `session_lookup` returns NULL rather than a stale pointer for an expired session.
- **Establishes:** nothing on its own — see the callee analysis below, which is where this gets interesting.
- **Depended on by:** L114 and L116 both.

```c
// L114-L115
if (!s)
    return -ENOENT;
```
- **What:** Rejects a lookup miss.
- **Why here:** Guards the dereference at L116.
- **Assumes:** NULL is the only failure representation `session_lookup` uses.
- **Establishes:** `s != NULL` for the remainder of the function.
- **Depended on by:** L116, L117.

```c
// L116-L117
s->refcount++;
*out = s;
```
- **What:** Records the borrow and publishes the pointer.
- **Why here:** After the NULL guard; the increment precedes publication so the caller never holds a pointer
  that has not been counted.
- **Assumes:** the caller holds `g_session_lock`, since `refcount++` is not atomic (`refcount` is a plain
  `int` at `src/session.h:L22`).
- **Establishes:** the borrow is accounted for.
- **Depended on by:** every subsequent `session_release`.

**Cross-Function Dependencies:**

- **Callee `session_lookup` (internal, src/session.c:L94-L110):** read in full. It walks `g_sessions` and
  returns the matching entry. Two properties matter here and neither is visible from `session_acquire`:
  1. It compares `s->id == id` (L102) but **does not check `s->state`**. An entry in state
     `SESSION_CLOSING` (set at L204 of `session_close`, which does not remove the entry from the table until
     L211) still matches. So `session_acquire` can take a reference to a session that is mid-teardown.
     `session_acquire` reads as though liveness were established; it is established nowhere.
  2. It returns NULL only when the walk falls off the end (L109). The expiry check at L104 `continue`s past
     expired entries rather than deleting them, so expiry is enforced only on the lookup path — an entry
     already borrowed by another caller stays reachable through that caller's pointer.
- **Callers:** `proto_handle_request` (`src/proto.c:L94`) — takes `g_session_lock` at L91, so the locking
  precondition holds. `admin_dump_session` (`src/admin.c:L51`) — **no lock acquisition anywhere in the
  function**; the increment at L116 races. That path assumes a precondition nothing establishes.
- **Shared state:** `g_sessions` with `session_lookup`, `session_close`, `session_reap`. `s->refcount` with
  `session_release`.
- **Invariant coupling:** the table's central invariant — every entry's refcount equals the number of
  outstanding borrows — holds only if every acquire is under the lock. One of the two callers breaks that.

**Open Questions:**
- unclear; need to inspect whether `g_session_lock` is documented as a caller precondition anywhere. Nothing
  in `session.h` states it, and only one of two callers honors it.
- unclear; need to inspect `session_reap` (`src/reap.c`) to know whether it can free an entry whose refcount
  is non-zero. That decides whether the `SESSION_CLOSING` window above is reachable in practice.

---

## What this example shows

The `SESSION_CLOSING` observation and the unlocked-caller observation are both invisible from
`session_acquire` alone. Reading only the subject function, `session_lookup` returning non-NULL reads as
though it established liveness. Reading the callee shows it establishes identity and nothing more.

Both are recorded as unenforced assumptions with the line that should have enforced them. Neither is called a
use-after-free or a race condition, neither gets a severity, and no fix is proposed — the hunting phase makes
those calls with the whole system model in front of it.

Note also what the record does *not* do: there is no invariant invented to reach a count, and blocks that do
one thing get one line each.

---

## The same shape in Solidity

The format does not change between domains; see [DOMAIN_NOTES.md](DOMAIN_NOTES.md) for the full mapping. This
abbreviated record shows the contract idioms in place, and the same callee trap in a different dialect.

```solidity
// L61
function withdraw(uint256 amount) external {
    require(_debit(msg.sender, amount), "insufficient");   // L62
    (bool ok, ) = msg.sender.call{value: amount}("");      // L63
    require(ok, "transfer failed");                        // L64
    totalDeposits -= amount;                               // L65
}
```

**Inputs & Assumptions:**
- `amount` (uint256): user-specified. Trust: **untrusted**.
- Implicit: `msg.sender`, `balanceOf[msg.sender]` (L12), `hasCreditLine[msg.sender]` (L13).
- Precondition: the caller's balance covers `amount`. **Established by `_debit`, and only on one of its two
  paths** — see below.

**Outputs & Effects:**
- Storage writes: `balanceOf[msg.sender]` inside `_debit` (L48, L52); `totalDeposits` at L65.
- External interaction: `msg.sender.call{value: amount}` (L63) — value transfer to an arbitrary address.
- No event emitted on withdrawal. Off-chain accounting cannot observe this path.

**Block-by-Block (L62-L65):**
- **What:** debits the balance, sends the ether, then decrements the running total.
- **Why here:** the debit precedes the transfer, which reads as checks-effects-interactions.
- **Assumes:** `_debit` returning true means the balance covered the amount.
- **Establishes:** nothing the later lines can rely on — `totalDeposits` at L65 lands *after* the external
  call at L63, so it is not in effect during re-entry.

**Cross-Function Dependencies:**
- **Callee `_debit` (internal, L44-L54):** read in full. Two paths, and they do not agree.
  - Default path (L50-L52): `if (balanceOf[account] < amount) return false;` then subtracts. The bound holds.
  - Credit-line path (L46-L49): when `hasCreditLine[account]` is set, it subtracts inside an `unchecked`
    block and returns true **without comparing balance to amount**. For those accounts the caller's
    precondition is established by nothing, and the subtraction wraps instead of reverting.
- **Invariant coupling:** `sum(balanceOf) == totalDeposits` is the contract's central invariant. It is
  maintained on the default path and not on the credit-line path.

**Open Questions:**
- unclear; need to inspect who can set `hasCreditLine` and whether it is ever cleared (`L13` declares it;
  no setter appears in this file).

Note what the record does *not* say: it does not call L63 a reentrancy vulnerability or the `unchecked` block
an integer underflow, and it proposes no fix. It says where each precondition is established, and names the
one that is established nowhere. The hunting phase takes it from there.
