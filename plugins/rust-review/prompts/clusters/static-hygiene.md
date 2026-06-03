---
name: cluster-static-hygiene
kind: cluster
consolidated: false
covers:
  - cargo-lint-config # CARGOLINT
  - msrv-mismatch     # MSRV
  - deprecated-api    # DEPRECAPI
---

# Cluster: Static hygiene

Project-wide hardening rules. ID prefixes: `CARGOLINT`, `MSRV`, `DEPRECAPI`.

Missing `// SAFETY:` / `# Safety` documentation is covered by the `SAFETYDOC` pass in **unsafe-boundary** — do not re-audit here.

## Phase A

Read `Cargo.toml`, `rust-toolchain.toml`, `clippy.toml` if present.

```
Grep: pattern="unsafe_code|missing_docs|warnings"
Grep: pattern="mem::uninitialized|MaybeUninit::uninit\(\)\.assume_init"
```

Run finders in declared order.
