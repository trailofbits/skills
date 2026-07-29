# Rust Release Practices

Use `cargo` for everything: building, testing (`cargo test`), formatting
(`cargo fmt`), linting (`cargo clippy`), and documentation (`cargo doc`).

## Toolchain and edition

- Prefer the latest stable compiler and the latest edition for new code.
- If older-compiler support matters, declare it explicitly with
  `package.rust-version` in `Cargo.toml` and test that version in CI.

## Crate-level lints

Add these to `lib.rs`/`main.rs` before release:

```rust
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
```

- `forbid(unsafe_code)` prevents direct `unsafe` (transitive uses through
  dependencies are still allowed). Omit only for crates that genuinely need
  `unsafe`, and isolate those blocks with `// SAFETY:` comments.
- `deny(missing_docs)` fails the build when a public API lacks a rustdoc
  comment.
- Optionally forbid explicit panics in library code with
  `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` — but
  note panics are often appropriate; apply this only where callers need
  `Result`-based error handling throughout.

## Supply-chain checks

- [`cargo audit`](https://github.com/rustsec/rustsec) in CI flags
  dependencies with known advisories.
- [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny) additionally
  enforces license and source policies on the dependency tree — useful for
  catching a copyleft dependency slipping into a permissively licensed
  project.

## Publishing to crates.io

- Use crates.io [trusted publishing](https://crates.io/docs/trusted-publishing)
  (OIDC from GitHub Actions) instead of long-lived API tokens.
- [`cargo release`](https://github.com/crate-ci/cargo-release) manages
  version bumps, tagging, and pushing. A common configuration in
  `Cargo.toml`, with the actual publish performed by CI:

```toml
[package.metadata.release]
publish = false # handled by GitHub Actions
push = true
```

- Set `license` (SPDX expression), `description`, `repository`, and
  `documentation` in `Cargo.toml`; crates.io and docs.rs surface these
  directly. docs.rs builds documentation automatically on publish.

## Binary distribution

For tools with end-user binaries, use
[cargo-dist](https://github.com/axodotdev/cargo-dist) or
[goreleaser](https://goreleaser.com/) to build multi-platform release
artifacts and installers from CI on each tag.
