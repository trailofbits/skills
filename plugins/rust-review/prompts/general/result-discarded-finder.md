---
name: result-discarded-finder
description: Detects Result<T,E> silently dropped via `let _ =`, ignoring errors that must propagate
---

**Finding ID Prefix:** `RESDISC`.

**Gates:**

1. `let _ = expr;` OR a `Result`-returning expression in statement position without `?`, `match`, `if let`, or `unwrap`/`expect` (Clippy `must_use` would catch the latter).
2. The expression is genuinely a silently-discarded `Result` / `#[must_use]` value — i.e. the error is not handled on any path (no `?`, `match`, `if let`, `unwrap`/`expect`, or assignment that inspects it). Gate on *that*, **not** on your guess at impact. Record the likely impact (write / lock-acquire / validation / crypto-verification failure) as context in the finding, but file **every** confirmed silent discard regardless of perceived severity — the fp+severity judge ranks it. Dropping a confirmed discard because it looks low-impact is forbidden (worker protocol rule 4: never gate filing on guessed severity/security-relevance).

**FPs:**

- Caller explicitly accepts the result, documented with a comment.
- Result is an `io::Result<()>` from a logging call.

**Patch:** propagate via `?` or `.map_err(...)?`.
