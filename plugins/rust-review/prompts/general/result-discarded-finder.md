---
name: result-discarded-finder
description: Detects Result<T,E> silently dropped via `let _ =`, ignoring errors that must propagate
---

**Finding ID Prefix:** `RESDISC`.

**Gates:**

1. `let _ = expr;` OR a `Result`-returning expression in statement position without `?`, `match`, `if let`, or `unwrap`/`expect` (Clippy `must_use` would catch the latter).
2. The discarded error variant could be security-relevant (write failure, lock-acquire failure, validation failure, crypto verification result).

**FPs:**

- Caller explicitly accepts the result, documented with a comment.
- Result is an `io::Result<()>` from a logging call.

**Patch:** propagate via `?` or `.map_err(...)?`.
