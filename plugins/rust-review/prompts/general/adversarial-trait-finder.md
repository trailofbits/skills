---
name: adversarial-trait-finder
description: Detects unsafe code trusting return values from user-supplied trait impls (Read, Iterator, Hash, etc.)
---

**Finding ID Prefix:** `TRAITADV`.

**Bug shape (research):** library accepts `T: Read`, allocates a buffer based on `T::read()`'s reported size, and writes via unchecked unsafe. Hostile `impl Read for HostileType` returns a size larger than the actual buffer → OOB write.

**Gates:**

1. Public generic API with a trait-bounded parameter (`T: Read`, `T: Iterator`, `T: Hasher`, `T: ExactSizeIterator`, custom traits).
2. The implementation uses the trait method's return value (size, count, index, hash) as input to an `unsafe` operation OR to a length-allocating call (`Vec::with_capacity`, `Vec::set_len`).
3. No defensive check ensures the reported value matches reality (e.g., `ExactSizeIterator::len()` is a hint, not a guarantee — `unsafe` code must not trust it).

**FPs:**

- Trait is sealed (`pub trait T: sealed::Sealed`).
- The reported value is only used as a heuristic and validated downstream.

**Patch:** treat trait method outputs as untrusted; bound them; never feed directly into `set_len` or `get_unchecked`.
