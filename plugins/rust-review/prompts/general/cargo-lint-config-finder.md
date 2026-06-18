---
name: cargo-lint-config-finder
description: Detects missing or insufficient [lints] configuration in Cargo.toml for security-relevant warnings
---

**Finding ID Prefix:** `CARGOLINT`.

**Gates:**

1. Read `Cargo.toml` (plus a workspace `[lints]`, `clippy.toml`, and any `#![deny(...)]` crate attributes), and check whether the crate actually contains `unsafe`.
2. Flag a security-relevant hygiene gap — but gate each lint to a real code condition:
   - **`unsafe_code`** is allow-by-default and only meaningful for crates intended to be **unsafe-free**. `deny(unsafe_code)` makes any crate that legitimately uses `unsafe` fail to build, so do **not** flag its absence on a crate that contains `unsafe`; recommend `forbid`/`deny(unsafe_code)` only for crates with no `unsafe`.
   - **`clippy::undocumented_unsafe_blocks` / `clippy::missing_safety_doc`** are only relevant when the crate contains `unsafe`. (`clippy::missing_safety_doc` is already warn-by-default — the gap is failing to escalate it to `deny`.)
   - **`unused_must_use`** is already **warn-by-default** in rustc; its mere absence from `[lints]` is the normal state, not a misconfiguration. Only an explicit `allow` (a downgrade), or failure to escalate to `deny`, is noteworthy.
3. Each filed finding must name the specific lint AND the concrete code characteristic that makes it relevant (e.g. "crate has `unsafe` blocks but does not `deny(clippy::undocumented_unsafe_blocks)`").

**Out of scope (not security):** `clippy::pedantic` and `missing_docs` are opinionated style/documentation lints (allow-by-default) that most projects intentionally leave off; promoting them breaks idiomatic builds and they are not security-relevant — do not file them as security findings.

**FPs to reject:** a crate that already escalates the relevant lints (in `Cargo.toml`, a workspace `[lints]`, `RUSTFLAGS`, or a `#![deny(...)]` crate attribute); a crate that legitimately uses `unsafe` and therefore cannot `deny(unsafe_code)`.

**Patch:** suggest a `[lints.rust]` / `[lints.clippy]` block that **escalates the applicable** lints to `deny` — only those whose code condition holds (e.g. `unsafe_code` only for unsafe-free crates) — (see [Cargo `[lints]`](https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section) and [Clippy lints](https://doc.rust-lang.org/clippy/)). Do not cite a Testing Handbook Rust security checklist — none is published at [appsec.guide Languages](https://appsec.guide/docs/languages/) yet.
