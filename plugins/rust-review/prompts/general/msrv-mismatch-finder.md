---
name: msrv-mismatch-finder
description: Detects missing MSRV declaration or use of features past the declared MSRV
---

**Finding ID Prefix:** `MSRV`.

**Gates:**

1. `Cargo.toml` has no `rust-version` field, OR
2. `rust-version` is set but the code uses post-MSRV features (e.g., `let-else` on `rust-version = 1.60`).

**Patch:** set explicit `rust-version`; pin in CI via `cargo +<msrv> check`.
