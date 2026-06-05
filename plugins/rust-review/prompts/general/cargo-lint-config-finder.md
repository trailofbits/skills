---
name: cargo-lint-config-finder
description: Detects missing or insufficient [lints] configuration in Cargo.toml for security-relevant warnings
---

**Finding ID Prefix:** `CARGOLINT`.

**Gates:**

1. Read `Cargo.toml`.
2. Missing or `allow`'d: `unsafe_code`, `clippy::pedantic`, `missing_docs`, `unused_must_use`, `clippy::undocumented_unsafe_blocks`, `clippy::missing_safety_doc`.

**Patch:** suggest a `[lints.rust]` / `[lints.clippy]` block that promotes the gated warnings above (see [Cargo `[lints]`](https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section) and [Clippy lints](https://doc.rust-lang.org/clippy/)). Do not cite a Testing Handbook Rust security checklist — none is published at [appsec.guide Languages](https://appsec.guide/docs/languages/) yet.
