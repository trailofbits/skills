---
name: unwrap-on-untrusted-finder
description: Detects unwrap/expect on Result/Option flowing from attacker-controlled input
---

**Finding ID Prefix:** `UNWRAP`.

**Gates:**

1. `.unwrap()`, `.unwrap_err()`, or `.expect("...")` site.
2. The `Result`/`Option` is produced by parsing/decoding/lookup of external input (HTTP request, file content, IPC message, CLI arg, env var, untrusted serde input).
3. The panic is not reliably recovered. A `std::panic::catch_unwind` wrapper only counts as recovery under a `panic = "unwind"` build — under `panic = "abort"` (common on servers/embedded) `catch_unwind` is a no-op and the panic aborts the whole process, so an `unwrap` it "guards" is still a DoS and must be filed. Likewise `catch_unwind` cannot reliably stop a panic crossing an FFI/`extern` boundary. Treat "inside `catch_unwind`" as recovery only when the build is `panic = "unwind"` and the panic does not cross FFI.

**FPs (reject):**

- Statically infallible: parsing a hardcoded `&str` constant; unwrapping `Some(x)` where the producing path is provably surjective.
- Inside test code (`#[test]`, `#[cfg(test)]`).
- After explicit `is_ok()` / `is_some()` check immediately preceding.

**Patch:** replace with `?`, `match`, `unwrap_or(default)`, `unwrap_or_else(|e| ...)`, or `ok_or(err)`.
