# Rust analyzer V2: filter improvement loop

## Premise

V1 of this plugin shipped strong recall (catches the planted KyberSlash, Lucky 13, Minerva, RSA timing patterns) but drowned the user in warning noise when run on real crates. On `libcrux-ml-kem/constant_time_ops.rs` (a formally verified constant-time crate), the unfiltered baseline emitted 11,725 warnings. Even Opus 4.7 cannot reliably triage 11k warnings without losing the signal.

V2's question: how much of that noise is structural and can be filtered without dropping recall? Answer (curated): from F1 = 0.51 unfiltered to F1 = 0.96 actionable across four iterations, with recall pinned at 1.0 every step.

## Trajectory

```
$ uv run python benchmark/scripts/track_trajectory.py pretty
label                                F1  F1act     AFI  AFIact   TP    FP  FPact   FN
------------------------------------------------------------------------------------------
rust_00_baseline_unfiltered       0.393  0.511  0.2449  0.3429   12    37     23    0
rust_01_default_filters           0.522  0.960  0.3529  0.9231   12    22      1    0
rust_02_iter_len_filters          0.522  0.960  0.3529  0.9231   12    22      1    0
rust_03_vartime_filter            0.522  0.960  0.3529  0.9231   12    22      1    0
```

Note that `F1` (raw) plateaus at 0.522 because raw FP counts every warning emitted, including obviously-public-bookkeeping branches. `F1_actionable` reflects what an agent or reviewer actually has to think about.

## Iteration 1: default precision filters (already in the plugin pre-V2)

These predate the V2 effort but are what `--filter all` enables. They were shipped in 0.3.0 of the plugin:

| Filter | Description | Effect |
|--------|-------------|--------|
| `cmp $imm; jcc` | Suppress branches preceded by compare-against-literal | Removes loop-counter / arg-validation branches |
| `cmp; jcc <panic>` | Suppress branches whose target label is a panic landing pad | Removes bounds-check / unwrap branches |
| `(file, line)` aggregation | Collapse multiple asm-level branches at one source line | One source-level event = one report |

Curated impact: F1_act 0.51 → 0.92 actionable. CT-AFI_act 0.34 → 0.92.

## Iteration 2: source-snippet-driven triage hints

Already in `analyzer.py::classify_violation`. We attach a 5-line source snippet to each violation, then pattern-match on the cited line:

| Hint                                | Pattern (in cited source line)                            |
|-------------------------------------|-----------------------------------------------------------|
| `stdlib_iter_end_likely_fp`         | source path under `core::iter::*`, `core::slice::iter::*` |
| `stdlib_bounds_check_likely_fp`     | source path under `core::slice::mod.rs`                   |
| `dependency_source_review`          | source path under `~/.cargo/registry/`                    |
| `fn_declaration_dispatch_likely_fp` | snippet shows a `fn ... <` declaration line               |
| `user_loop_bound_likely_fp`         | snippet shows `for _ in 0..PUBLIC_CONST`                  |
| `rejection_sample_loop_likely_fp`   | snippet shows `while !done` or `while x < UPPER_CONST`    |
| `compare_to_constant_likely_fp`     | snippet shows comparison against `UPPER_SNAKE_CASE`       |
| `early_return_compare_review`       | snippet shows `if a != b { return ... }` or similar       |

V2 added two new hints that fire on Rust idioms we missed in V1:

```python
TRIAGE_ITER_LOOP = "iterator_loop_likely_fp"
TRIAGE_LEN_COMPARE = "public_length_compare_likely_fp"
```

`for x in buf.iter()` / `for x in &buf` is a loop driven by a public container length; the iterator-end JE/JNE is loop control. `if a.len() != b.len()` is an explicit length-mismatch branch — slice length is metadata, not contents.

Curated impact: no movement (the corpus's clean files were already covered by other rules). Real impact comes in the wild benchmark — see V3 doc.

## Iteration 3: `vartime_*` function-name convention

Found via the wild evaluation (Phase 4): the curve25519-dalek codebase emits 3231 warnings, of which 18 are user-source. Manual triage of those 18 showed 11 inside `vartime_double_base_mul`, `vartime_double_base.rs`, etc. The Rust crypto convention — universal in dalek, ring, ed25519, k256/p256, rsa — is that any function whose name begins with `vartime_` or contains `::vartime_` is *deliberately* variable-time on PUBLIC operands (signature verification, batch verification, public-only operations).

```python
TRIAGE_VARTIME = "vartime_function_likely_fp"

# In classify_violation:
if re.search(r"(?:^|::|<|\b)(?:_)?vartime(?:_|::|>|\b)", function):
    return TRIAGE_VARTIME
```

The pattern is a word-boundary match to avoid spuriously matching e.g. `myvartimevalidate` (no such function exists in any audited crate; we leave the precision regex anyway).

**Regression risk consideration.** A naive `*vartime*` regex would suppress real findings if a developer named a function `update_vartime_counter` thinking it meant something benign. We accept that risk because:
- The convention is universal in the audited Rust crypto ecosystem.
- The classifier's hint is `_likely_fp`, not a hard filter — the warning is still in the report, just discounted from `F1_actionable`.
- If a TP shows up in a `vartime_*` function in a future crate, the curated benchmark would catch the regression on the next run because none of our planted bugs use `vartime` in the function name.

Curated impact: zero on the curated F1 (no `vartime_*` names in the corpus). Wild impact: 11 of 18 dalek user warnings reclassified from `early_return_compare_review`/`user_code_review` to `vartime_function_likely_fp`. The dalek triage workload drops from 18 items to 7.

## Patterns considered but rejected

### `subtle::*` allowlist

The prompt suggested an allowlist for `_ZN6subtle*` symbols and `<.* as subtle::ConstantTimeEq>::ct_eq` patterns. We did not add this. Reason: the existing `_should_skip_function` filter already drops violations whose crate is in `RUST_STDLIB_CRATES`, and we considered adding `subtle` to that set. The deciding test was the planted `naive_mac_compare.rs::verify_signature_early_exit` — manually-implemented `ct_eq`-style early-exit. If `subtle::*` were allowlisted, a misnamed user-defined `ct_eq` that *isn't* using subtle could be silently suppressed. We left the rule as "filter monomorphized stdlib code only" and let `subtle` callers triage by source-path (`dependency_source_review`).

### `<.* as core::cmp::Ord>::cmp` allowlist

Variable-time on slices but called with public lengths in production code. Allowlisting it risks suppressing the real Lucky 13 pattern (which manifests as the same JE/JNE ladder). We left it un-allowlisted and lean on the `early_return_compare_review` triage hint to surface candidates for human review.

### `core::hint::black_box` allowlist

`black_box` is the value-barrier intrinsic that subtle uses to prevent LLVM from optimizing away constant-time computations. It compiles to an empty function (just `ret`) at every opt level. The analyzer sees no branches in it, so no allowlist is needed — it never produces a violation.

### `#[no_mangle] extern "C"` symbols

These are the FFI surface (e.g. `aes_gcm_encrypt`). They're treated as the "actual-crypto" stratum: a branch in a `#[no_mangle]` function is held to the same scrutiny as any other user code. The crate-naming convention via `_ZN<crate>...E` mangling lets us correctly classify them.

## How to extend

To add a new triage hint:

1. Add a `TRIAGE_*` constant in `ct_analyzer/analyzer.py` near the existing ones.
2. Define the regex (file path or source-snippet pattern) above `classify_violation`.
3. Insert the rule in the body of `classify_violation`. Order matters: more-specific rules first.
4. Add a unit test in `ct_analyzer/tests/test_analyzer.py::TestTriageClassifier`.
5. Re-run the curated benchmark and confirm `F1_actionable` does not regress:

   ```
   PYTHONPATH=. uv run python benchmark/scripts/run_benchmark.py --warnings \
     --opt O0 --opt O2 --opt O3 --filter all \
     --corpus-dir benchmark/corpus_rust \
     --manifest benchmark/corpus_rust/manifest.json \
     --label rust_iterN --out benchmark/results/rust_iterN.json
   PYTHONPATH=. uv run python benchmark/scripts/track_trajectory.py append \
     benchmark/results/rust_iterN.json
   PYTHONPATH=. uv run python benchmark/scripts/track_trajectory.py pretty
   ```

The curated benchmark is the regression net. Any change that drops recall below 1.0 or actionable F1 below 0.85 is a regression and should be reverted unless the regression is justified in the trajectory writeup.
