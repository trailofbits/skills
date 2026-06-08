---
name: serialize-struct-mismatch-finder
description: Detects manual Serialize impls where the declared element count diverges from the number of fields actually serialized
---

**Finding ID Prefix:** `SERFIELDS`.

**Bug shape:** A manual `Serialize` impl calls `serializer.serialize_struct("X", N)` (or `serialize_tuple`/`serialize_seq` with an explicit `len`) where `N` does not match the number of `serialize_field`/`serialize_element` calls emitted on every code path. Length-prefixed binary formats (bincode, `serde-binary`) truncate or misframe the payload, so round-tripping yields different data. This pattern is caught by the Trail of Bits `wrong_serialize_struct_arg` dylint.

**Gates:**

1. A manual `impl Serialize` uses `serialize_struct`, `serialize_tuple`, or `serialize_seq` with an explicit count literal.
2. The literal differs from the actual field/element call count on at least one path (conditional `serialize_field`, early return, skipped optional field).

**FPs:**

- Count matches on every reachable path.
- Format is self-describing (JSON, TOML) and ignores the declared length.
- `#[derive(Serialize)]` is used; count is compiler-generated.

**Patch:** Match the declared count to emitted fields on every path, or eliminate the manual impl with `#[derive(Serialize)]`.
