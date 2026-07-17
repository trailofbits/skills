---
name: str-slice-boundary-finder
description: Detects str range slicing / split_at / truncate at an attacker-controlled byte index that may fall off a UTF-8 char boundary, panicking
---

**Finding ID Prefix:** `STRSLICE`.

**Gates:**

1. Range slice (`&s[a..b]`), `split_at`/`split_at_mut`, or `String::truncate` on a `str`/`String`.
2. The byte index is derived from untrusted input or byte-length arithmetic (taint trace), not from `find`/`char_indices`/`match` on the same string.
3. No boundary proof on the path (`is_char_boundary`, `.get(range).is_some()`, or the string is known ASCII).

**FPs:**

- Index came from `find`/`char_indices`/`split` on the same string (always a valid boundary).
- Already guarded by `is_char_boundary`, or uses `s.get(a..b)`.
- String proven ASCII, or index is `0`/`s.len()`.

**Patch:** use `s.get(a..b)` and handle `None`; or `split_at_checked`; or derive the index from `char_indices()`.

Distinct from `OOBIDX` (integer-index OOB on `Vec`/`[T]`): `STRSLICE` panics *in bounds* when the index lands inside a multi-byte char.
