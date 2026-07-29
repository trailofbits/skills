---
name: adversarial-trait-finder
description: Detects unsafe code trusting return values from user-supplied trait impls (Read, Iterator, Hash, etc.)
---

**Finding ID Prefix:** `TRAITADV`.

**Bug shape (research):** library accepts `T: Read`, allocates a buffer based on `T::read()`'s reported size, and writes via unchecked unsafe. Hostile `impl Read for HostileType` returns a size larger than the actual buffer → OOB write.

**Gates:**

1. Public generic API with a trait-bounded parameter (`T: Read`, `T: Iterator`, `T: Hasher`, `T: ExactSizeIterator`, custom traits).
2. The implementation feeds the trait method's return value (size, count, index, hash) into an `unsafe` operation or a length-trusting sink — `Vec::set_len`, `get_unchecked`, `ptr::write`/`copy_nonoverlapping` at a computed offset, or `from_raw_parts`. (`Vec::with_capacity`/`reserve` is **not** an OOB-write sink — it only reserves, with `len` still `0`, so a hostile size cannot write out of bounds through it — but an attacker-controlled capacity is a separate allocation/memory-exhaustion DoS; note that distinctly rather than as memory corruption.)
3. No defensive check ensures the reported value matches reality (e.g., `ExactSizeIterator::len()` is a hint, not a guarantee — `unsafe` code must not trust it).

**FPs:**

- Trait is sealed (`pub trait T: sealed::Sealed`).
- The reported value is only used as a heuristic and validated downstream.

**Patch:** treat trait method outputs as untrusted; bound them; never feed directly into `set_len` or `get_unchecked`.
