---
name: result-discarded-finder
description: Detects Result<T,E> silently dropped via `let _ =`, ignoring errors that must propagate
---

**Finding ID Prefix:** `RESDISC`.

**Gates:**

1. `let _ = expr;` OR a `Result`-returning expression in statement position without `?`, `match`, `if let`, or `unwrap`/`expect` (rustc's built-in `unused_must_use` lint — on by default, *not* a Clippy lint — warns on the bare-statement form, but it does **not** fire on `let _ = expr`, which is the more common silent discard).
2. The expression is genuinely a silently-discarded `Result` / `#[must_use]` value — i.e. the error is not handled on any path (no `?`, `match`, `if let`, `unwrap`/`expect`, or assignment that inspects it). Gate on *that*, **not** on your guess at impact. Record the likely impact (write / lock-acquire / validation / crypto-verification failure) as context in the finding, but file **every** confirmed silent discard regardless of perceived severity — the fp+severity judge ranks it. Dropping a confirmed discard because it looks low-impact is forbidden (worker protocol rule 4: never gate filing on guessed severity/security-relevance).

**FPs:**

- Caller explicitly accepts the result, documented with a comment.
- Result is a best-effort write to a purely cosmetic/diagnostic `stdout`/`stderr` sink with no correctness requirement. (Do **not** wave away a discarded `io::Result` from a write to a *persisted* / audit / integrity / network sink — that is a real finding; gate 2 forbids dropping it on a severity guess.)

**Patch:** propagate via `?` or `.map_err(...)?`.
