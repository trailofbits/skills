# Prompt: Rust constant-time analyzer benchmarking

Paste this whole file into a fresh Claude Code session whose working
directory is the root of this `skills` repository (the one containing
`plugins/constant-time-analysis/`).  Branch off `main` before starting.

---

## Goal

Apply the same evaluation rigor we already applied to the C/C++ version of
this analyzer (BoringSSL, OpenSSL, libsodium, mbedTLS) to **Rust** crypto
code.  The four artefacts to produce are direct analogues of the C ones:

  - `benchmark/RUST_MECHANICAL_EVAL.md`  - curated mechanical triage
  - `benchmark/RUST_V2_DESIGN.md`        - filter improvement loop
  - `benchmark/RUST_V3_DWARF.md`         - source attribution from rustc DWARF
  - `benchmark/results/wild_<crate>_v3.json` for each production crate

Read these as templates before starting:

  * `plugins/constant-time-analysis/benchmark/MECHANICAL_EVAL.md`
  * `plugins/constant-time-analysis/benchmark/V2_DESIGN.md`
  * `plugins/constant-time-analysis/benchmark/V3_DWARF.md`
  * `plugins/constant-time-analysis/benchmark/WILD_EVAL.md`

The CT-AFI metric, the filter framework (`ct_analyzer/filters.py`), and
the harnesses (`benchmark/scripts/run_benchmark.py`,
`benchmark/scripts/run_wild.py`) all already exist.  You are extending,
not re-creating.

## Phase 0: Confirm what's already there

The analyzer's `RustCompiler` class is already in
`ct_analyzer/analyzer.py`; it builds with `rustc --emit=asm -C opt-level=N`.
The single curated Rust file (`ct_analyzer/tests/test_samples/decompose_vulnerable.rs`)
exists but isn't integrated into the benchmark corpus.

Run:

```bash
PYTHONPATH=. python3 ct_analyzer/analyzer.py --warnings ct_analyzer/tests/test_samples/decompose_vulnerable.rs
```

to confirm the Rust path produces output.  If it doesn't, fix the parser
before doing anything else.

## Phase 1: curated Rust corpus + first numbers

Build a 12-15 item Rust corpus under
`plugins/constant-time-analysis/benchmark/corpus_rust/` with the same
three categories as the C one:

  1. **clean** (intentionally CT, expect 0 findings):
     - `subtle` crate primitives: `Choice`, `ConstantTimeEq::ct_eq`,
       `ConditionallySelectable::conditional_select`, `Choice::black_box`
     - `RustCrypto/utils/zeroize` style memzero
     - `chacha20` quarter-round (ARX, no branches on secrets)
     - X25519 / curve25519-dalek `FieldElement::mul`
     - HKDF/HMAC update loops over public-length input

  2. **vulnerable** (planted CT bugs, must detect):
     - **KyberSlash analogue**: `let q = secret_coef / GAMMA2;`
     - **Lucky13 analogue**: padding-loop bound is secret-derived
     - **Naive RSA modexp**: branch on `if exp & 1 == 1` per bit of secret exponent
     - **Naive MAC compare**: `if computed_mac == received_mac { ... }`
       (Rust's `PartialEq` on slices is variable-time - this is a real footgun)
     - **Bytewise constant_time_lt with branch**: `if a < b { 1 } else { 0 }`
       on secret operands

  3. **limitation_no_signal**:
     - AES T-table style (cache-timing) - tool can't see this; document it

Each `.rs` file must compile standalone with `rustc --edition=2021 --crate-type lib`.
Stub out external crates with minimal type aliases.

Write `benchmark/corpus_rust/manifest.json` with the same schema as
`benchmark/corpus/manifest.json`: per-file `label` + `ground_truth_violations`
list with `line` + `kind` (`div_on_secret`, `branch_on_secret`,
`memcmp_on_secret`, `secret_loop_bound`).

## Phase 2: baseline metric + curated benchmark

Extend `benchmark/scripts/run_benchmark.py` to support a
`--language rust` flag (or just `--corpus-dir`) and call it with:

```bash
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py \
  --warnings --opt O0 --opt O2 --opt O3 --filter all --smart-fusion \
  --corpus-dir benchmark/corpus_rust \
  --manifest benchmark/corpus_rust/manifest.json \
  --label rust_baseline --out benchmark/results/rust_00_baseline.json
```

You should see CT-AFI somewhere in 0.005 - 0.02 with the unfiltered baseline,
similar to the C result.  If it's already 0.5+ on the unfiltered baseline,
either the corpus is too soft or rustc at -O2 is optimising the planted
bugs away in a way the C compiler didn't (likely - LLVM is aggressive).
Investigate: `--opt O0` should always show the planted DIV/branch.

## Phase 3: improvement loop with held-out validation

Same arc as the C version (read `V2_DESIGN.md`).  The filter framework
in `ct_analyzer/filters.py` already exists; you are adding Rust-specific
patterns to the existing `CT_FUNCTION_PATTERNS` list, not creating a new
module.  The framework is language-agnostic.

For Rust specifically, the allowlist patterns to add include:

  - `subtle::*::*` - `_ZN6subtle6Choice` and friends
  - `<.* as subtle::ConstantTimeEq>::ct_eq` patterns
  - `core::hint::black_box`
  - `<.* as core::cmp::Ord>::cmp` (DISCUSS: this is variable-time on
    slices, but called with public lengths in most production code -
    making it allowlisted is risky.  See discussion in
    `MECHANICAL_EVAL.md` about Lucky13.)
  - `RustCrypto`-shape symbols: `_ZN10aes_gcm.*` etc.
  - `core::ptr::write_volatile`
  - The `_ZN`-prefix mangled name patterns

**Iterate carefully.**  After each filter change, run the curated
benchmark and confirm F1 doesn't regress.  In the C version we caught
two regressions this way:
  - Lucky13 over-suppression by an over-broad `_validate_*` regex
  - The non-secret extension to errors killing `mbedtls_mpi_mod_int`

Same trap exists in Rust: `<*ConstantTimeEq>::ct_eq_lazy` for example
is meant to be CT but a generic `_lazy$` regex would suppress real
findings too.  Be specific.

Track the trajectory in `benchmark/results/rust_trajectory.jsonl`:

```bash
PYTHONPATH=. python3 benchmark/scripts/track_trajectory.py append \
  benchmark/results/rust_iter1.json
```

(extend `track_trajectory.py` if it hardcodes the C trajectory file path).

Target curated F1 0.85+ before moving on.

## Phase 4: wild benchmark on production crates

Pick **three** large, audited Rust crypto crates.  Recommended:

  - `briansmith/ring` (production TLS crypto)
  - `RustCrypto/AEADs` (chacha20poly1305, aes-gcm, etc.)
  - `dalek-cryptography/curve25519-dalek` (heart of Ed25519 / X25519)

Or, if `ring` is too heavy, substitute `rustls/rustls` (mostly wraps
crypto primitives - finds different patterns) or
`RustCrypto/elliptic-curves`.

For each:

```bash
mkdir -p benchmark/wild_rust && cd benchmark/wild_rust
git clone --depth=1 <repo-url>
cd <crate>
RUSTFLAGS="-C debuginfo=2" cargo build --release
```

The `.o` files appear under `target/release/build/<crate>-*/out/*.o` AND
`target/release/deps/*.o`.  Find them all.  rustc embeds DWARF in the `.o`
when `-C debuginfo=2` is set, so the `objdump -d -l` flow we already
have in `run_wild.py` should Just Work.

Add a build-validity precondition at the top of the wild run, like the
C version got after the silent-mbedTLS-submodule-failure incident: refuse
to print headlines when `n_objects == 0` or `n_instructions < 1000`.

Run the wild benchmark with default filters:

```bash
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild_rust/<crate>/target/release \
  --label <crate>_v3 --out benchmark/results/wild_<crate>_v3.json
```

## Phase 5: mechanical triage

Same approach as the C wild eval (`WILD_EVAL.md`):

  1. Triage **all** errors finding-by-finding.  Read the source.
     Classify each as TP / FP-public / FP-doc / FP-loop.  Pay special
     attention to `subtle::ConstantTimeEq` callers vs `==` on `&[u8]`.
  2. Sample **30 warnings** with a fresh seed (use `seed=44` to match
     the C v3 numbering convention).  Triage each.

For each finding the source path lands at, look at:
  - The function's parameter types: `&[u8]` named `key` / `secret` /
    `mac` / `tag` / `signature` is a strong signal it operates on a secret.
  - Whether the function is in a `#[cfg(test)]` module or named
    `*_test` / `*_self_test` / `tests::*` (suppress with the same
    test-function regex used by `_TEST_FUNC_RE` in `filters.py`).
  - Whether the file lives in `src/` (production) vs `tests/`,
    `examples/`, `benches/`, `fuzz/` (non-production - suppress).

## Phase 6: write up + commit

Three writeups, mirroring the C ones:

  - `benchmark/RUST_MECHANICAL_EVAL.md` (curated triage at the best v3 config)
  - `benchmark/RUST_V2_DESIGN.md` (the filter improvement trajectory)
  - `benchmark/RUST_V3_DWARF.md` (source attribution + final numbers)

Each commit message should report curated F1, wild totals, error TP/FP,
and triage-time savings vs unfiltered baseline.  Push to a feature
branch, do not open a PR unless asked.

## Pitfalls specific to Rust (read before starting)

1. **`bytes::PartialEq` is the silent footgun.**  Rust developers writing
   `if computed_mac == expected_mac` get a variable-time compare and the
   compiler will not warn.  This is the equivalent of C's `memcmp` on
   secrets - and unlike C, there's no separate function name to allowlist
   or blocklist.  The vulnerable corpus *must* include this pattern; the
   filter must detect it.  In MIR / asm, this lowers to `core::slice::eq`
   or a memcmp-style compare loop with an early exit on first mismatch.

2. **LLVM optimisation tier matters.**  rustc at `-O0` (`-C opt-level=0`)
   emits naive code with idiv on every `/`.  At `-O2` (release default),
   constant divisions become Barrett/multiply-shift sequences and many
   branches collapse into `cmov`.  The smart-fusion model from the C
   version (errors any-O, warnings only at O2/O3) applies directly.

3. **Mangled symbol names are uglier than C++ in BoringSSL.**  Rust's
   Itanium-mangled names for generic instantiations look like
   `_ZN10elliptic_curve9scalar_xx12ScalarXxArith11is_zero_ct$LT$T$GT$$LP$$RP$17h12345abcdef`.
   Demangling with `rustfilt` makes the allowlist patterns much easier
   to write.  The harness should optionally pipe through `rustfilt`
   (`cargo install rustfilt`) before regex-matching.

4. **`#[no_mangle] extern "C"` exports look like C symbols.**  These are
   usually the FFI surface of the crate; treat them as the
   "actual-crypto" stratum, not the protocol stratum.

5. **`core::hint::black_box` is the value barrier.**  Allowlist it.

6. **rustc inlines aggressively.**  A finding may attribute to an
   unexpected source file because the actual instruction came from
   inlined code in another crate.  The `non-secret` filter should look
   at the function name in the disassembly, not just the file path.

7. **Cargo `dev-dependencies` get linked into bench / test binaries.**
   Filter `target/release/` not `target/debug/` and skip directories
   matching `tests/`, `benches/`, `fuzz/`, `examples/`.

## What success looks like

Curated F1 within 0.05 of the C number (so 0.80 - 0.90).  Wild totals
showing >50% reduction from unfiltered baseline after applying the
filter set.  At least one TP found in the wild that survives expert
triage (or a documented argument that none exist - the C version's
TP was `mbedtls_mpi_mod_int` reachable from RSA prime gen; the Rust
analogue might be a `subtle`-bypass call site somewhere in `ring`).

Mechanical triage of all errors plus a 30-warning held-out sample is
non-negotiable - that's the data that tells you whether the metric is
honest.

Report back with the four artefact paths, the headline numbers (curated
F1, wild totals, error TP/FP, triage-time delta), and any regressions
the curated benchmark caught during the loop.
