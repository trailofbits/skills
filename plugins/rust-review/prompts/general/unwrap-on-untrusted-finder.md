---
name: unwrap-on-untrusted-finder
description: Detects unwrap/expect on Result/Option flowing from attacker-controlled input
---

**Finding ID Prefix:** `UNWRAP`.

**Gates:**

1. `.unwrap()`, `.unwrap_err()`, or `.expect("...")` site.
2. The `Result`/`Option` is produced by parsing/decoding/lookup of external input (HTTP request, file content, IPC message, CLI arg, env var, untrusted serde input).
3. The call site is not inside `std::panic::catch_unwind` AND the surrounding scope does not have a panic recovery wrapper.

**FPs (reject):**

- Statically infallible: parsing a hardcoded `&str` constant; unwrapping `Some(x)` where the producing path is provably surjective.
- Inside test code (`#[test]`, `#[cfg(test)]`).
- After explicit `is_ok()` / `is_some()` check immediately preceding.

**Patch:** replace with `?`, `match`, `unwrap_or(default)`, `unwrap_or_else(|e| ...)`, or `ok_or(err)`.
