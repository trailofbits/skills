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
rg seed: "unsafe_code|missing_docs|warnings"
rg seed: "mem::uninitialized"  # deprecated API (DEPRECAPI); the modern `MaybeUninit::uninit().assume_init()` is a UNINITREAD/memory-safety concern, not seeded here
```

Run finders in declared order.
