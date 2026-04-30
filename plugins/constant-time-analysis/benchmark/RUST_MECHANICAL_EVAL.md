# Rust constant-time analyzer: mechanical evaluation

## Purpose

Validate the Rust analyzer's detection rates against a manifest-driven curated corpus and document the per-finding triage on three production crypto crates. The numbers here back the headlines we ship in the README.

## Curated corpus

`benchmark/corpus_rust/` ships 13 `.rs` files in three categories:

- **clean (6)**: `ct_eq_bytes`, `ct_select`, `zeroize_volatile`, `chacha20_quarter_round`, `curve25519_field_mul`, `hkdf_expand`. These are the textbook constant-time primitives. Expected: 0 errors, 0 actionable warnings.

- **vulnerable (6)**: `kyberslash`, `lucky13`, `rsa_modexp_naive`, `naive_mac_compare`, `branch_lt_secret`, `dsa_nonce_reduce`. Each plants 1–3 ground-truth violations annotated in `manifest.json`. Each compiles standalone with `rustc --edition=2021 --crate-type lib`.

- **limitation_no_signal (1)**: `aes_ttable`. AES with T-table lookups — a real cache-timing leak that an instruction-level analyzer cannot detect. We ship it to make the limitation explicit, not to pretend we cover it.

Manifest schema (v2): each ground-truth entry pairs a target function with a violation kind (`div_on_secret`, `branch_on_secret`, `memcmp_on_secret`, `secret_loop_bound`). Matching is on `(function-name-substring, mnemonic-class)` rather than line number — rustc's `.loc` directives often attribute inlined-from-stdlib operations to their stdlib source path even when the function attribution is correct, and we exploit that to score honestly.

## Headline numbers (final config)

```
$ uv run python benchmark/scripts/run_benchmark.py --warnings \
    --opt O0 --opt O2 --opt O3 --filter all \
    --corpus-dir benchmark/corpus_rust \
    --manifest benchmark/corpus_rust/manifest.json \
    --label rust_03_vartime_filter \
    --out benchmark/results/rust_03_vartime_filter.json
```

| Metric          | Unfiltered | Default filters | + iter/len rules | + vartime rule |
|-----------------|-----------:|----------------:|-----------------:|---------------:|
| TP              | 12         | 12              | 12               | 12             |
| FP raw          | 37         | 22              | 22               | 22             |
| FP actionable   | 23         | 1               | 1                | 1              |
| FN              | 0          | 0               | 0                | 0              |
| Recall          | 1.000      | 1.000           | 1.000            | 1.000          |
| F1 (raw)        | 0.393      | 0.522           | 0.522            | 0.522          |
| **F1 (actionable)** | **0.511** | **0.960**   | **0.960**        | **0.960**      |
| CT-AFI          | 0.245      | 0.353           | 0.353            | 0.353          |
| **CT-AFI (actionable)** | **0.343** | **0.923** | **0.923**     | **0.923**      |

**Curated F1 = 0.96** (actionable). The vartime/iter/len rules don't move the curated metric (the corpus has none of those patterns) but they do dramatically reduce noise in the wild benchmark — see `RUST_V3_DWARF.md`.

The **actionable** variants subtract two classes of report from the FP count:

1. Reports whose `triage_hint` ends in `_likely_fp` — the agent dispenses with these by reading the hint string.
2. Reports inside a function listed in any GT entry — the reviewer triages the whole function in one pass; extra branches inside a known-vulnerable function cost zero additional time.

The single residual actionable FP is in `clean/curve25519_field_mul.rs` at `let r0 = r0 + c * 19;`. rustc emits a u128 carry-overflow JB; the radix-2^51 reduction never actually overflows but the analyzer can't prove that without arithmetic reasoning. Documented as a known limitation.

## Per-file triage (final config)

| File                                         | Label       | TP/GT | FP_act | Notes                                                                        |
|----------------------------------------------|-------------|-------|--------|------------------------------------------------------------------------------|
| `clean/ct_eq_bytes.rs`                       | clean       | 0/0   | 0      | XOR-OR accumulator with `read_volatile`; FPs all hint to `_likely_fp`        |
| `clean/ct_select.rs`                         | clean       | 0/0   | 0      | Bitmask blend; analyzer reports zero violations                              |
| `clean/zeroize_volatile.rs`                  | clean       | 0/0   | 0      | `write_volatile` loops; loop-control branches hinted as iter-end             |
| `clean/chacha20_quarter_round.rs`            | clean       | 0/0   | 0      | Pure ARX; loop-control branches hinted as iter-end                           |
| `clean/curve25519_field_mul.rs`              | clean       | 0/0   | 1      | u128 carry overflow JB on `r0 + c * 19` — known limitation                   |
| `clean/hkdf_expand.rs`                       | clean       | 0/0   | 0      | Public-length output loop; iter/len classifier handles                       |
| `vulnerable/kyberslash.rs`                   | vulnerable  | 2/2   | 0      | IDIV on parameterized `q` detected at every opt level                        |
| `vulnerable/lucky13.rs`                      | vulnerable  | 2/2   | 0      | Secret-derived loop bound + early-exit MAC compare detected with `--warnings` |
| `vulnerable/rsa_modexp_naive.rs`             | vulnerable  | 3/3   | 0      | Square-and-multiply branch + IDIV in modinv detected                         |
| `vulnerable/naive_mac_compare.rs`            | vulnerable  | 1/1   | 0      | Manual early-exit loop detected; pcmpeqb / bcmp paths correctly NOT flagged  |
| `vulnerable/branch_lt_secret.rs`             | vulnerable  | 2/2   | 0      | `if a < b` and `while k >= q` branches detected                              |
| `vulnerable/dsa_nonce_reduce.rs`             | vulnerable  | 2/2   | 0      | Minerva conditional subtraction + DSA `% q` detected                         |
| `limitation_no_signal/aes_ttable.rs`         | limitation  | 0/0   | 0      | Cache timing — by design not detected                                        |
| **Total**                                    |             | **12/12** | **1** | All planted bugs detected; one residual u128-carry FP                       |

## Notable triage learnings

### `[u8; N] == [u8; N]` is constant-time at -O2

A long-standing piece of Rust crypto folklore says `==` on byte slices is "the silent footgun" because it lowers to a variable-time compare. We initially planted three "naive MAC compare" bugs based on that belief. The actual asm tells a more nuanced story:

- `[u8; 32] == [u8; 32]` (fixed-size array) lowers to `pcmpeqb` SIMD compare — fully constant-time at the per-byte level.
- `&[u8] == &[u8]` (slice) emits a `cmpq; jne` on the public *length*, then calls `bcmp`. The contents-compare is in libc, outside the user's asm.
- A manual `for i in 0..n { if a[i] != b[i] { return false; } }` loop *does* emit per-byte JE/JNE — actually variable-time.

Only the third pattern is a planted bug at the asm level, and it's the only one we ship in the corpus. The first two we keep as anti-fixtures: visible code that the analyzer correctly does *not* flag as variable-time, with a docstring explaining why.

### Recall-first scoring

Every config in the trajectory has recall = 1.0. We never trade recall for precision in this codebase because the cost of a missed timing leak in production crypto is unbounded; the cost of a noisy report that an Opus session has to triage is bounded by reading the source snippet. The `triage_hint` mechanism + actionable metric is how we let agents discount noise without the analyzer dropping reports.

## Files

- `benchmark/corpus_rust/manifest.json` — ground truth
- `benchmark/results/rust_00_baseline.json` — unfiltered
- `benchmark/results/rust_03_vartime_filter.json` — best config
- `benchmark/results/rust_trajectory.jsonl` — full trajectory across iterations
- `benchmark/scripts/run_benchmark.py` — harness with CT-AFI + F1 (raw / actionable)
- `benchmark/scripts/track_trajectory.py` — append + pretty-print
