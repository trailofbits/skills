---
name: recursive-deserialize-stack-overflow-finder
description: Detects deserialization of untrusted input into recursive types without an enforced depth limit (serde_yaml/toml/ron/custom Deserialize, or serde_json with raised/bypassed limit)
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
   - **`serde_json`** enforces a 128-frame limit by default — usually safe. Flag if `Deserializer::disable_recursion_limit()` is called, or if the value is parsed via a `Visitor`/`Deserialize` impl that itself recurses without budget (custom impls bypass the framework's check on each frame).
   - **`serde_yaml`**, **`toml`**, **`ron`**, **`ciborium`**, **`bincode`**, **`postcard`** do **not** enforce a default depth limit. Any deserialize of untrusted bytes into a recursive type via these crates is a finding unless an explicit pre-parse depth check or `serde_stacker` is in place.
   - For HTTP frameworks, `axum::Json` and friends delegate to the underlying codec — they inherit its limit (or lack of one).
4. The call is reachable from an external trust boundary (request, file, env, IPC), not a constant.

**Why it matters:** the deserializer walks input depth recursively. At ~5–10 KB of stack per frame and a typical 8 MB main-thread stack on Linux (often 2 MB on async worker threads), an attacker submitting a few hundred to a few thousand levels of nested `[[[...]]]` or `{"a":{"a":{...}}}` crashes the worker. The crash is an *abort*, not a panic — `catch_unwind` does not help. `serde_json`'s built-in cap is the exception, not the rule; other codecs leave this to the caller.

This finder bounds what depths the later `RECURSEFMT` and `RECURSEDROP` finders need to consider. Run it first.

**FPs (reject):**

- `serde_json` codec, target type uses derived `Deserialize` only, no `disable_recursion_limit()` — the 128-frame cap applies.
- A pre-parse step explicitly bounds depth (length-prefix scan, structural tokenizer that refuses depth > N, `tokio_util::codec` with a depth-aware framer).
- The deserializer is wrapped in `serde_stacker::Deserializer`, which grows frames on the heap instead of the stack.
- Input source is statically trusted (config file shipped with the binary, `include_str!`, build script).

**Patch:**

- For `serde_yaml`/`toml`/`ron`/`ciborium`/`bincode`/`postcard`: wrap the deserializer in `serde_stacker::Deserializer`, OR pre-scan the input for maximum nesting depth and refuse > N (N typically 32–128 depending on protocol).
- For custom `Deserialize`/`Visitor` impls that recurse: thread a depth counter through `DeserializeSeed` and `Visitor::visit_*`, returning `Err(de::Error::custom("max depth"))` past the cap.
- For HTTP framework extractors, attach a body-size limit *and* a depth limit — body size alone does not bound depth (`[[[[...]]]]` is dense).
- Do **not** rely on `serde_json::Deserializer::disable_recursion_limit()` "just for performance" — removing the cap re-introduces the bug on the JSON codec too.
