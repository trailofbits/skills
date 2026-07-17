---
name: recursive-format-stack-overflow-finder
description: Detects format/Display/Debug/Serialize/log macros applied to recursive types reachable from untrusted input, where depth-proportional stack growth causes an uncatchable abort
---

**Finding ID Prefix:** `RECURSEFMT`.

**Gates:**

1. A formatting/serializing/logging sink applied to a value `v`:
   - `format!`, `print!`/`println!`, `eprint!`/`eprintln!`, `write!`/`writeln!`, `dbg!`
   - `v.to_string()`, `format!("{}", v)`, `format!("{:?}", v)`, `format!("{:#?}", v)`
   - `tracing::{trace,debug,info,warn,error}!` / `log::{...}!` with `{}`/`{:?}` of `v`
   - `serde_json::{to_string,to_vec,to_writer}` (and `_pretty` variants), `serde_yaml::to_string`, `toml::to_string`, `ron::to_string`, `bincode::serialize`, `ciborium::ser::into_writer`
   - `anyhow!`/`bail!`/`thiserror`-derived `Display` chains that embed `v` via `{:?}`/`{}`
2. The static type of `v` (or a field of `v` reached during formatting) is in `rec_map` from Phase A — i.e., recursive directly or via `serde_json::Value` / `serde_yaml::Value` / `toml::Value` / `syn::*` / `proc_macro2::TokenStream` / similar.
3. `v` is reachable from an untrusted source identified in Phase B, OR `v` is constructed via repeated `clone`/`push`/append loops on untrusted data so that depth can grow with input size.
4. Neither the type's `Display`/`Debug`/`Serialize` impl nor a wrapper at the call site bounds depth. Specifically:
   - No `Formatter::precision()` / max-depth check in a hand-written `impl Debug`/`impl Display`.
   - No truncating wrapper (`pretty_assertions::Comparison`, custom `Truncated<&T>`, `tracing` field redaction, etc.).
   - No `serde_stacker` deserializer/serializer wrapping the codec.

**Why it matters:** stack overflow is uncatchable — `catch_unwind` does **not** trap it. The **entire process** aborts (a stack overflow in any thread aborts the whole process via the runtime's SIGSEGV handler — never just the offending thread), regardless of `panic` strategy. `serde_json` enforces a 128-deep recursion limit on **parse**, but **no** symmetric limit exists on `Serialize`/`Debug`/`Display`. A deep value therefore reaches a formatting sink only when a parse cap did **not** bound it: a value decoded by a codec with no default limit (`bincode`, `postcard`), a value decoded by a codec whose default recursion limit was raised/disabled (`serde_json::Deserializer::disable_recursion_limit()`, `ron::Options::without_recursion_limit`, `toml`'s `unbounded` feature — note `serde_json`/`serde_yaml`/`toml`/`ron`/`ciborium` all default-cap at ~128/128/~80/128/256), or a value built programmatically (repeated `push`/`clone`). A value parsed by *default* `serde_json` is ≤128 deep — too shallow to overflow on re-emit — so the format-side hazard does **not** apply to it (see `RECURSEDES` for the parse-side cap). Error chains (`anyhow`, `eyre`, `thiserror` with `#[source]`) compound the risk: a Display of one error transitively formats every wrapped cause.

**FPs (reject):**

- The type is recursive in definition but the codebase provably bounds depth at construction (e.g., a parser that rejects depth > N before insertion, *and* the same type is not constructed by any other path).
- The formatting site is statically unreachable from untrusted input (constants, build-script-time values, `#[cfg(test)]`).
- A hand-written `impl Debug`/`impl Display` already implements depth limiting (read the body — recursion guarded by an explicit counter or `f.precision()`).
- The recursive field is behind a `Lazy`/`OnceCell` populated only from trusted config.

**Patch:**

- Wrap the sink in a truncating display: implement `Debug` manually with a depth counter that bails to `…` past a threshold, or pass through a `Truncated<&T, N>` newtype that does the same.
- For `serde_json`/etc. re-emission of untrusted values, route through `serde_stacker::Serializer` (grows heap-allocated stack frames) or precompute a depth check and refuse > N.
- For log lines, drop `{:?}` of recursive values and emit shape summaries (`len`, `kind`, top-level keys) instead of the full structure.
- For error chains, render with `anyhow::Chain` / explicit iteration rather than nested `Display` recursion.
