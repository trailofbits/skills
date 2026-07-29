---
name: string-comparison-finder
description: Detects security decisions that use substring/prefix/suffix predicates where full equality is required, or mix case-sensitivity inconsistently
---

**Finding ID Prefix:** `STRCMP`.

**Bug shape:** A security or routing decision calls `starts_with`/`ends_with`/`contains` where full `==` equality is required, enabling bypass (e.g. allowlist check on `"/admin"` matches `"/admin-public"`). Alternatively, case-sensitive `==` and case-insensitive `eq_ignore_ascii_case` are mixed across the same value class (host, path, file extension), creating path confusion.

**Gates:**

1. The comparison gates a security-relevant decision: auth check, allowlist/denylist, host/origin validation, file-extension filter, routing.
2. It uses a substring/prefix/suffix predicate (`starts_with`, `ends_with`, `contains`) where exact identity is required, OR mixes case-sensitive and case-insensitive comparisons inconsistently across equivalent checks.

**FPs:**

- Prefix/suffix match is the explicitly intended semantics (e.g. MIME-type prefix, path hierarchy traversal).
- Inputs are pre-normalized to a canonical form before comparison.
- Comparison is non-security display or formatting logic.

**Patch:** Use `==` or `.eq()` for identity decisions; normalize case uniformly via `eq_ignore_ascii_case` or `.to_lowercase()` and document the chosen semantics.
