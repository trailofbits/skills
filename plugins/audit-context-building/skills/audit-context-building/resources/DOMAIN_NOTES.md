# Domain Notes

The format never changes. Whatever the target, you are always asking the same four questions up front —
what are the pieces, how does the outside world get in, who is on the other side, and what data survives
between calls — and then, per function, what must be true, what it takes on faith, and what it calls.

What changes is the answers, and what counts as a call you cannot see inside. That is what this file maps.

| | ways in | who's on the other side | data that sticks around | calls you can't see inside |
| --- | --- | --- | --- | --- |
| Smart contracts | `external` / `public` function | caller, owner, relayer, oracle, other protocols | storage slots | an address whose code isn't in the project |
| C / C++ source | exported function, parser, syscall or IPC handler | remote peer, local user, other threads | globals, statics, long-lived heap | a linked library shipped without source |
| Decompiled / firmware | task entry, interrupt handler, protocol handler | radio peer, LAN host, serial console | fixed addresses, NVRAM, DMA regions | a symbol the decompiler never resolved |
| Web services (Go, Rust, Python) | route handler, RPC method, queue consumer | logged-in user, anonymous caller, internal service | database rows, cache entries, sessions | a third-party API |

## Contracts

The original target of this plugin, and the one where "external call" carries the most weight. A call to an
address whose code is not in scope is the black-box case: record the value and calldata sent, and the
outcomes not excluded — revert, a hostile return value, and re-entry into the caller before its own state
writes land. Whether the write lands before or after the call is usually the whole question in "why here".

Implicit inputs are larger than they look: the caller identity, the block timestamp, the gas left, and
anything read from another contract. Under effects, storage writes and emitted events are separate lines,
because indexers depend on the events and solvency depends on the writes.

Watch for `unchecked` blocks and assembly. Both suspend guarantees the surrounding code is written as though
it still has, which is exactly the shape the continuity rule exists to catch — a caller relies on a checked
subtraction that a callee performs unchecked.

## C and C++ source

Bounds, lifetimes, and integer width carry most of the invariants. An out-parameter is the classic continuity
trap: the caller checks the return code and uses the out-parameter, and one path through the callee returns
success without writing it, or writes it without bounding it.

Record who owns each pointer and until when. `free` on one path and not another, a borrow that outlives the
lock that protected it, and a length in `int` compared against a `size_t` are all structural facts, not
findings. Note which calls are behind `#ifdef` — a path that only exists in one build configuration is still
a path, and orientation should say which configuration was read.

## Decompiled binaries and firmware

Three things differ, and they all land in orientation.

**Function boundaries are themselves a finding.** Before anything can be ranked, the functions have to be
recovered, and the recovery is fallible. Say which entry points were identified, how, and what was left
unattributed. `FUN_80104a2c` is a name that tells you nothing — the rule against inferring behavior from a
name is not a caution here, it is the default condition.

**Go top-down from task entry points.** Starting at RTOS task entries, interrupt handlers, and protocol
handlers and working downward beats exploring outward from whatever looked interesting. The entrypoint list
is the work queue.

**Most callees are black boxes, and that is the normal case rather than an exception.** A call to an address
with no recovered body — a ROM thunk, a syscall, a library the decompiler did not resolve — gets the same
treatment as an unknown external contract: what is passed, what is assumed, what is not excluded. A bound
that is never established in the visible listing is an assumption with `establishedBy: "nothing found"`, and
that is a complete and useful answer, not a failure to finish.

Keep a coverage record alongside the dossier: which tasks and handlers have been analyzed and which have not.
Without it there is no way to tell a clean subsystem from an unread one.

## Services

Logic and authorization carry more weight than memory safety. The trust boundary is usually a middleware
chain, so the continuity rule points at the framework: a handler is safe because something upstream
authenticated the request, and that something is a decorator, a route registration, or a config file rather
than a call in the handler's body. Record where the check actually lives, and whether every route registered
on that path gets it.

Concurrency is persistent state. Two handlers that read-modify-write the same row without a transaction are
coupled even though neither calls the other; that belongs in shared state and invariant couplings.
