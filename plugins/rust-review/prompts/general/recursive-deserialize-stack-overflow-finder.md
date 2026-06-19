---
name: recursive-deserialize-stack-overflow-finder
description: Detects deserialization of untrusted input into recursive types without an enforced depth limit (bincode/postcard/custom Deserialize, or a codec like serde_json/serde_yaml/toml/ron/ciborium with its default recursion limit raised or bypassed)
---

**Finding ID Prefix:** `RECURSEDES`.

**Gates:**

1. A deserialize entry point reads from an untrusted source:
   - `serde_json::{from_str,from_slice,from_reader,from_value}`
   - `serde_yaml::{from_str,from_slice,from_reader}`
   - `toml::from_str` / `toml::from_slice`
   - `ron::{from_str,de::from_reader}`
   - `ciborium::de::from_reader`, `bincode::deserialize`, `postcard::from_bytes`
   - `#[derive(Deserialize)]` types reached via `axum::Json`, `actix_web::web::Json`, `rocket::serde::json::Json`, `warp::body::json`, gRPC `prost` decode, etc.
2. The target type is recursive (in `rec_map` from Phase A), or is a library recursive type (`serde_json::Value`, `serde_yaml::Value`, `toml::Value`, `ron::Value`, `ciborium::Value`, `syn::*`).
3. No depth-limiting wrapper is in effect on this call site:
   - **`serde_json`** enforces a 128-frame limit by default — usually safe. Flag **only** if `Deserializer::disable_recursion_limit()` is called, or if a custom impl re-drives parsing *outside* the serde `Deserializer` (e.g. it captures raw bytes and calls `from_str`/`from_slice` again, or hand-rolls its own parser). An ordinary recursive `Visitor`/`Deserialize` that recurses through the normal serde API (`next_element`/`next_value`) is **still capped at 128** by the Deserializer — do **not** flag it on that basis alone.
   - **`serde_yaml`** (128), **`toml`** (~80 via `toml_edit`), **`ron`** (128), and **`ciborium`** (256) all enforce a built-in recursion limit by default during deserialization — usually safe, like `serde_json`. Flag them **only** if that limit is explicitly raised/disabled (e.g. `ron::Options::without_recursion_limit`, `toml`'s `unbounded` feature) or a custom out-of-band parser bypasses the codec. Only **`bincode`** and **`postcard`** genuinely impose **no** default depth limit — for those, any deserialize of untrusted bytes into a recursive type is a finding unless an explicit pre-parse depth check or `serde_stacker` is in place.
   - For HTTP frameworks, `axum::Json` and friends delegate to the underlying codec — they inherit its limit (or lack of one).
4. The call is reachable from an external trust boundary (request, file, env, IPC), not a constant.

**Why it matters:** the deserializer walks input depth recursively. At ~5–10 KB of stack per frame and a typical 8 MB main-thread stack on Linux (often 2 MB on async worker threads), an attacker submitting a few hundred to a few thousand levels of nested `[[[...]]]` or `{"a":{"a":{...}}}` crashes the worker. The crash is an *abort*, not a panic — `catch_unwind` does not help. A built-in parse cap is the **norm**, not the exception (`serde_json` 128, `serde_yaml` 128, `toml` ~80, `ron` 128, `ciborium` 256); `bincode` and `postcard` are the codecs that leave depth to the caller.

This finder bounds what depths the later `RECURSEFMT` and `RECURSEDROP` finders need to consider. Run it first.

**FPs (reject):**

- `serde_json` codec, target type uses derived `Deserialize` only, no `disable_recursion_limit()` — the 128-frame cap applies.
- A pre-parse step explicitly bounds depth (length-prefix scan, structural tokenizer that refuses depth > N, `tokio_util::codec` with a depth-aware framer).
- The deserializer is wrapped in `serde_stacker::Deserializer`, which grows frames on the heap instead of the stack.
- Input source is statically trusted (config file shipped with the binary, `include_str!`, build script).
- `serde_yaml`/`toml`/`ron`/`ciborium` with **default** options — these enforce built-in recursion caps (128 / ~80 / 128 / 256). Treat as safe unless the cap is raised/disabled (`without_recursion_limit`, the `unbounded` feature, etc.) or bypassed by a custom parser.

**Patch:**

- For `bincode`/`postcard` (no default cap), or any codec whose limit was raised/disabled: wrap the deserializer in `serde_stacker::Deserializer`, OR pre-scan the input for maximum nesting depth and refuse > N (N typically 32–128 depending on protocol). For `serde_yaml`/`toml`/`ron`/`ciborium`, simply keep their default recursion limit (do not call `without_recursion_limit` / enable `unbounded`).
- For custom `Deserialize`/`Visitor` impls that recurse: thread a depth counter through `DeserializeSeed` and `Visitor::visit_*`, returning `Err(de::Error::custom("max depth"))` past the cap.
- For HTTP framework extractors, attach a body-size limit *and* a depth limit — body size alone does not bound depth (`[[[[...]]]]` is dense).
- Do **not** rely on `serde_json::Deserializer::disable_recursion_limit()` "just for performance" — removing the cap re-introduces the bug on the JSON codec too.
