---
name: serialize-struct-mismatch-finder
description: Detects manual Serialize impls where the declared element count diverges from the number of fields actually serialized
---

**Finding ID Prefix:** `SERFIELDS`.

**Bug shape:** A manual `Serialize` impl calls `serializer.serialize_struct("X", N)` / `serialize_tuple(N)` (these take a bare `usize`), or `serialize_seq(Some(N))` / `serialize_map(Some(N))` (these take `Option<usize>`), where the declared count does not match the number of `serialize_field`/`serialize_element`/`serialize_entry` calls emitted on every code path. The impact is **format-dependent**, so name the right format:

- **`serialize_seq` / `serialize_map`:** bincode (and other non-self-describing length-prefixed formats) writes the declared `Some(N)` as the element-count prefix, so a wrong `N` truncates or misframes the payload and round-tripping yields different data.
- **`serialize_struct` / `serialize_tuple`:** bincode/postcard **ignore** the declared count entirely (struct/tuple arity is known from the Rust type at decode time), so a wrong `N` there is inert. The count-mismatch corruption instead surfaces in formats that emit a per-struct element header — MessagePack (`rmp-serde`) and CBOR (`ciborium` / `serde_cbor`) — where a wrong header count produces malformed output.

This pattern is caught by the Trail of Bits `wrong_serialize_struct_arg` dylint.

**Gates:**

1. A manual `impl Serialize` uses `serialize_struct`/`serialize_tuple` with an explicit count, or `serialize_seq`/`serialize_map` with an explicit `Some(N)`.
2. The declared count differs from the actual field/element call count on at least one path (conditional `serialize_field`, early return, skipped optional field).

**FPs:**

- Count matches on every reachable path.
- Format is self-describing (JSON, TOML) and ignores the declared length.
- The call is `serialize_struct`/`serialize_tuple` **and** the only target format is bincode/postcard, which discard the declared struct/tuple arity (the corruption requires a count-prefixing format — MessagePack/CBOR — or a `serialize_seq`/`serialize_map` length).
- `#[derive(Serialize)]` is used; count is compiler-generated.

**Patch:** Match the declared count to emitted fields on every path, or eliminate the manual impl with `#[derive(Serialize)]`.
