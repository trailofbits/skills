# rust-review

Rust security code review plugin. Bug-class coverage comes from empirical bug-shape research across 245 memory-corruption, 177 unsound safe-API, 150 denial-of-service, and 60 thread-safety advisories in the [RustSec Advisory Database](https://rustsec.org/advisories/) (1,078 entries) and audits. Orchestration matches `c-review`, which uses the published [Testing Handbook C/C++ security checklist](https://appsec.guide/docs/languages/c-cpp/); the handbook [Languages](https://appsec.guide/docs/languages/) section has no Rust checklist yet.

## Usage

Invoke with `/rust-review:rust-review`. The skill will prompt for:

- **Threat model** (`REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH`)
- **Worker model** (`haiku` / `sonnet` / `opus`)
- **Severity filter** (`all` / `medium` / `high`)
- **Scope subpath** (optional — defaults to whole repo)

Findings + SARIF are written to `$(pwd)/.rust-review-results/<iso-timestamp>/`.

## Overview

Inputs (`AskUserQuestion`): threat model, scope subpath (optional), worker model, severity filter.

From these inputs the orchestrator detects Rust capability flags (`has_unsafe`, `has_ffi`, `has_concurrency`, `has_async`) over the scope and selects clusters from `prompts/clusters/manifest.json`. Each cluster groups related bug classes anchored on a shared mental model and runs as one parallel worker.

Always-on clusters:

- **unsafe-boundary** (consolidated) — Unsafe Reachability Analysis (URAPI), `transmute` misuse, pointer-cast hazards via `as` (PTRCAST), raw-pointer arithmetic, `#[repr(C)]` layout, enum discriminant and niche validity (ENUMUB), `// SAFETY:` documentation rules, `debug_assert!`-guarded safety invariants.
- **memory-safety** — UAF via dangled raw pointer, double-free via `ptr::read`, invalid-free via assignment-to-uninit, uninitialized-read via premature `assume_init`, `Vec::set_len` without slot init (SETLEN), buffer overflow via safe→unsafe index propagation, union variant misread, panic-unsafe custom container drop (PANICUNWIND). Per-pass `requires: has_unsafe`.
- **panic-dos** — resource exhaustion DoS (RESEXHAUST, P0), `unwrap`/`expect` on untrusted input, arithmetic overflow, reachable `unreachable!`/`assert!`, vector OOB indexing, non-char-boundary `str` slicing panics (STRSLICE).
- **recursion-dos** — stack-overflow aborts (uncatchable, distinct from panics) on recursive types: unbounded deserialization depth (`serde_yaml`/`toml`/`ron`/custom `Deserialize`), recursive `Display`/`Debug`/`Serialize` on attacker-shaped values, implicit `Drop` of `Box<Self>`-style chains.
- **error-handling** — discarded `Result`s, panics inside `Drop`, lossy `From`/`Into` and `as` casts, lossy UTF-8 / OS-string / path conversions (LOSSYSTR).
- **logic-correctness** — `Ord`/`Eq`/`Hash` invariant violations, hostile generic trait impls, closure-panic across unsafe scaffolding, NaN/Inf edge cases.
- **static-hygiene** — Cargo lint config, MSRV, deprecated APIs (`mem::uninitialized`).
- **resource-handling** — raw file-descriptor double-close and leak (RAWFD).

Conditional clusters:

- **concurrency-locking** (`has_concurrency`, consolidated) — `MutexGuard` double-lock from lexical scope, ABBA ordering, `Condvar` wait without notifier, channel starvation, `Once::call_once` reentrancy, signal-handler / callback reentrancy.
- **concurrency-data-race** (`has_concurrency`) — non-atomic atomic sequences, `unsafe impl Sync` over interior mutability, missing `Send`/`Sync` bounds, cross-process shared-memory races, unsynchronized `static mut` (STATICMUT).
- **ffi-cross-language** (`has_ffi`) — `CString::as_ptr` dangling, ABI mismatch, `#[repr(C)]` padding leak, unaligned references to `#[repr(packed)]` fields (PACKEDREF), opaque-pointer ownership confusion, FFI-owned-memory drop mismatches, Rust closures across `extern "C"` without `catch_unwind`, `dyn Trait` fat pointers crossing FFI.
- **async-runtime** (`has_async`) — blocking calls in async, cancellation-unsafe `.await` sequences, `tokio::select!` branch bias.

Same orchestration as `c-review`: workers spawn foreground in a single message (with optional cache primer), write markdown-with-YAML-frontmatter finding files, then a dedup-judge merges duplicates, then an fp-judge assigns `fp_verdict` / `severity` / `attack_vector` / `exploitability`. SARIF safety net runs unconditionally.

## Architecture

```
coordinator: write context.md → build_run_plan.py → TaskCreate × M
          → spawn primer (foreground) → spawn M workers (parallel)
          → classify Phase-7 outcomes + write findings-index.txt
          → dedup-judge → fp-judge → SARIF safety net → return REPORT.md
```

| Subagent type | Purpose | Tool set |
|---|---|---|
| `rust-review:rust-review-worker` | Run assigned cluster, write findings | Read, Write, Edit, Grep, Glob, Bash |
| `rust-review:rust-review-dedup-judge` | Merge duplicates (runs **first**) | Read, Write, Edit, Glob |
| `rust-review:rust-review-fp-judge` | FP + severity + final reports (runs **second**) | Read, Write, Edit, Grep, Glob, Bash |

## Output directory layout

Default: `$(pwd)/.rust-review-results/<iso-timestamp>/`. Contains:

- `context.md` — resolved threat model, severity filter, scope, capability flags, Cargo manifest status
- `plan.json` — selected clusters + rendered worker spawn prompts (one per parallel worker)
- `worker-prompts/` — verbatim spawn prompts, one per worker (+ optional `cache-primer.txt`)
- `findings/` — one markdown file per finding (`<PREFIX>-NNN.md` with YAML frontmatter)
- `findings-index.d/` — per-worker shards listing finding paths (survive an orchestrator crash)
- `findings-index.txt` — canonical sorted union of shards
- `run-summary.md` — worker outcome table, retry/abort state, judge status
- `dedup-summary.md` — Tier 1/2/3 merge summary
- `fp-summary.md` — verdict counts and per-primary verdict table
- `REPORT.md` — human-readable final report grouped by severity, filtered per `severity_filter`
- `REPORT.sarif` — SARIF 2.1.0 export, idempotent (full overwrite), always written

## Not for

- Pure C / C++ codebases — use `c-review` instead.
- Smart contracts (Solana, NEAR, Ink!) — use `solana-vulnerability-scanner` or the contract-specific skill.
- Kernel-mode Rust without userspace allocator — coverage is incomplete; flag as advisory only.

## References

- [Rustonomicon](https://doc.rust-lang.org/nomicon/) — unsafe invariants
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
