# Constant-Time Analysis Benchmark

A precision/recall benchmark for the `ct_analyzer` against real production
C/C++ crypto code (BoringSSL, OpenSSL, libsodium, mbedTLS) plus synthetic
versions of canonical timing-attack patterns (KyberSlash, Lucky13, naive
RSA modexp, naive MAC check, AES T-table cache leak).

## Why the benchmark exists

Static CT analyzers in production hit a fatigue wall: every conditional branch
and every integer division gets flagged, so most findings are false positives,
so reviewers learn to skip findings, so real bugs slip through. To know whether
a change to the analyzer is *actually* better we need a metric that captures
all three forces: recall, precision, and reviewer-time-per-finding.

## CT-AFI (Constant-Time Alarm-Fatigue Index)

```
CT-AFI = F1 * exp(-T_total / T_budget)
```

Where `T_total` is the modeled minutes an expert spends triaging the report
and `T_budget = 60 min`. The exponential decay is the alarm-fatigue penalty:
two reports with the same F1 but very different sizes are not equally useful.

Per-finding triage cost is modeled as:

```
T_finding = 1 min  (base)
          + kind penalty   (DIV: +1, JCC: +1.5, CB*: +0.5, MEMCMP: +0.5)
          + 2 min if no source-line info
          + 2 min if function size > 50 instructions
```

These coefficients were chosen to match published audit anecdata - per-finding
review of a static-analysis hit takes an experienced reviewer 2-5 minutes
typical and >10 in deep call chains (Cifuentes & Scholz, FSE'12).

## Corpus (15 items)

| Label                  | Count | Examples                                        |
|------------------------|-------|-------------------------------------------------|
| clean                  |    10 | BoringSSL CRYPTO_memcmp, libsodium sodium_memcmp, mbedTLS ct_memcmp, OpenSSL CRYPTO_memcmp, ChaCha20, Curve25519 fe_mul/cswap |
| vulnerable             |     4 | KyberSlash, Lucky13, naive RSA, naive MAC check |
| limitation_no_signal   |     1 | AES T-table (cache-timing - undetectable by instruction-level analysis) |

Each item carries `ground_truth_violations` - line + kind tuples - that the
benchmark scorer matches against reported findings to compute TP/FP/FN.

## Running the benchmark

The three runner scripts (`run_benchmark.py`, `run_wild.py`,
`track_trajectory.py`) all dispatch by `--language={c,go,rust}` into a
language-specific harness.  Each language path keeps its own argparse
contract and result-JSON schema -- the unification is purely a CLI
convenience for the entry point.  Pass `--language <lang> --help` to
see the per-language flags.

```bash
# Baseline (no filters, all opt levels) on the C corpus
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language c \
    --warnings --opt O0 --opt O2 --opt O3 \
    --label baseline --out benchmark/results/00_baseline.json

# Recommended config (all filters + smart opt fusion) on the C corpus
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language c \
    --warnings --opt O0 --opt O2 --opt O3 \
    --filter ct-funcs,memcmp-source,non-secret,aggregate \
    --smart-fusion --label tuned --out benchmark/results/tuned.json

# Same script, Go corpus
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language go \
    --corpus-dir benchmark/corpus_go --manifest benchmark/corpus_go/manifest.json \
    --warnings --opt O0 --opt O2 --opt O3 --filter all --smart-fusion \
    --label go_tuned --out benchmark/results/go_tuned.json

# Same script, Rust corpus
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language rust \
    --corpus-dir benchmark/corpus_rust --manifest benchmark/corpus_rust/manifest.json \
    --warnings --opt O0 --opt O2 --opt O3 --filter all \
    --label rust_tuned --out benchmark/results/rust_tuned.json

# Wild-mode (production code) -- C library, Go workspace, Rust crate
PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language c \
    --root benchmark/wild/libsodium --label libsodium

PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language go \
    --workspace benchmark/wild_go/workspace \
    --target stdlib:crypto/internal/fips140/mlkem --label go_stdlib

PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language rust \
    --root benchmark/wild_rust/<crate>/target/release \
    --label <crate> --out benchmark/results/wild_<crate>.json

# Trajectory: C/Go renders against trajectory.jsonl, Rust against rust_trajectory.jsonl
PYTHONPATH=. python3 benchmark/scripts/track_trajectory.py --language c
PYTHONPATH=. python3 benchmark/scripts/track_trajectory.py --language rust pretty
```

## Improvement trajectory

The full filter stack + smart fusion lifts CT-AFI by ~94x relative to the
unfiltered baseline. The curve is super-linear early (each new filter knocks
out a clear FP class) and tapers toward an asymptote in the high-0.4s region:

```
iter   label             P       R      F1   n_find  T_min  CT_AFI   delta
   0   baseline       0.167  0.900   0.281      54   239.5  0.0052
   1   ct-funcs       0.265  0.900   0.409      34   149.5  0.0339  +0.0287
   2   +aggregate     0.364  0.800   0.500      22    95.5  0.1018  +0.0679
   3   +secret-flow   0.476  1.000   0.645      21    79.0  0.1729  +0.0711
   4   +DIV-aggregate 0.588  1.000   0.741      17    68.0  0.2385  +0.0656
   5   +strict-ns     0.625  1.000   0.769      16    64.0  0.2647  +0.0262
   6   GT-recalibrate 0.625  0.833   0.714      16    64.0  0.2458  -0.0189
   7   +struct-CT     0.714  0.909   0.800      14    55.0  0.3199  +0.0741
   8   O2/O3 only     0.857  0.545   0.667       7    24.5  0.4432  +0.1233
   9   +smart-fusion  0.889  0.727   0.800       9    32.5  0.4654  +0.0222
  10   +call-sites    0.900  0.818   0.857      10    34.0  0.4864  +0.0210
```

The final asymptotic regime (iterations 8-10) shows the expected diminishing
returns: each subsequent change only nudges CT-AFI by ~+0.02. The remaining
gap is largely fundamental - cache-timing (T-table) leaks are invisible to
instruction-level analysis, and a single residual loop-counter branch in a
secret-handling cipher round needs real data flow analysis to suppress.

## Filters

| Filter             | What it suppresses                                      |
|--------------------|---------------------------------------------------------|
| `ct-funcs`         | Findings inside vetted CT primitives (CRYPTO_memcmp, sodium_*, mbedtls_ct_*, fe_cswap, ChaCha20 round funcs) |
| `compiler-helpers` | Findings inside libgcc/compiler-rt helpers (`__udivdi3`) |
| `memcmp-source`    | *Adds* findings for memcmp/strcmp on secret-named args  |
| `non-secret`       | All findings in functions with no secret-named param    |
| `aggregate`        | Multiple same-family findings in a function -> one      |
| `--smart-fusion`   | Errors from any opt; warnings only from O2/O3           |

Filters compose: pass a comma-separated list to `--filter` or use `--filter all`.

## Limitations of this benchmark

- **Compiler/version coupling**: Results depend on the host clang version.
  KyberSlash idiv survives on some compilers and is hidden on others.
- **Synthetic vulnerable items**: Lucky13/RSA/etc. are short reproductions,
  not the original CVEs. Real codebases have additional context the
  analyzer can exploit.
- **Cost model is heuristic**: Per-finding triage time is a single-coefficient
  approximation, not measured against real reviewer logs.
- **Corpus size**: 15 items is enough to detect order-of-magnitude changes,
  not 5% deltas. For tighter measurement, expand the corpus to 50-100 items.
