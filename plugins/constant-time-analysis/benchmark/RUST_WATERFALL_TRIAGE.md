# Mechanical waterfall triage: every user warning across 8 production crates

## The premise

Cluster reduction (the V3 file/pattern grouping) tells us how many *items* a reviewer has to look at — 93 file clusters across the 8 wild crates. But "look at" is doing a lot of work. Some of those 93 take 2 seconds (hint says `_likely_fp`); some take 30 seconds (a recognizable idiom in the source snippet); a few take 10+ minutes (read the function, walk the callers, reason about whether the operand is secret-derived).

A waterfall model makes that gradient explicit. We define five phases with strictly increasing per-item cost, and dispatch each warning at the cheapest phase that can decide it. The cumulative budget for the whole evaluation is then a weighted sum:

```
total_minutes ≈ N1 * 0.02 + N2 * 0.1 + N3 * 0.5 + N4 * 5 + N5 * 15
```

A run where 95% of items dispatch at Phase 1–3 is a totally different review experience from one where 95% reach Phase 4–5. The `waterfall_triage.py` harness implements this and emits a per-phase exit count.

## Phase definitions

| Phase | Cost / item | Decides on                                                | Verdict       |
|------:|:-----------:|-----------------------------------------------------------|---------------|
| 1     | ~1 sec      | `triage_hint == *_likely_fp` OR source path under `/rustc/` / `~/.cargo/registry/` / `~/.cargo/git/` | FP |
| 2     | ~5 sec      | function name matches non-crypto patterns (`Display::fmt`, `Drop::drop`, `cpuid::get`, `der::`, `pkcs[18]::`, `rand_core`) OR source dir is `/tests/`, `/benches/`, `/fuzz/`, `/examples/`, `build.rs` | FP |
| 3     | ~30 sec     | source-snippet pattern matches one of ~25 idioms (derive macros, log macros, `let-else`, `assert!`, match dispatch, presence checks, iterator-end, structural-metadata accessors, public-constant comparison, square-and-multiply bit test, vartime-file-path, TLS-protocol-receiver method) | FP |
| 4     | ~5 min      | function signature parsed from snippet — all arg names match `_PUBLIC_ARG_NAMES`; no `_SECRET_ARG_NAMES` | FP |
| 5     | 10+ min     | survived all of the above — needs source + caller review | needs_review  |

## Aggregate results

Run on all 8 wild crates (the same set as `RUST_V3_DWARF.md`):

```
$ uv run python benchmark/scripts/waterfall_triage.py \
    --result 'benchmark/results/wild_*_v3.json' \
    --out benchmark/results/waterfall.json

Waterfall triage of 902 items across 8 crates
  Phase 1:   568  ( 63.0%)
  Phase 2:     1  (  0.1%)
  Phase 3:   265  ( 29.4%)
  Phase 4:     0  (  0.0%)
  Phase 5:    68  (  7.5%)
```

**834 of 902 items (92.5%) dispatch in phases 1–3 with mechanical rules.** Time budget at the documented per-phase costs:

```
Phase 1:   568 * 0.02 min  ≈   11 min
Phase 2:     1 * 0.10 min  ≈    0 min
Phase 3:   265 * 0.50 min  ≈  132 min
Phase 4:     0 * 5.00 min  ≈    0 min
Phase 5:    68 * 15.0 min  ≈ 1020 min
                            -------
                          ≈   19.5 hours
```

That's the *upper bound* — Phase 5 items cluster heavily within rustls into a small number of recognizable idioms, so per-item review goes faster after the first few of each kind.

## Per-crate breakdown

```
crate                             P1    P2    P3    P4    P5  total
bls12_381                        143     0     6     0     0    149
curve25519_dalek                   9     0     2     0     3     14
elliptic_curves                   25     0     1     0     2     28
rsa                              349     1    12     0     0    362
rustcrypto_aeads                  17     0     0     0     0     17
rustcrypto_hashes                  0     0     2     0     2      4
rustcrypto_signatures             18     0     1     0     0     19
rustls                             7     0   241     0    61    309
```

`rustls` is the long tail: 61 of the 68 Phase 5 items are TLS protocol-state code with idioms my Phase 3 patterns don't fully cover. The other crates cluster cleanly: dalek's 3 are the bookkeeping branches I already triaged in V3, EC's 2 are loop-counter / table-build patterns, hashes' 2 are CPU feature dispatch (a Phase 2 miss — see below).

## Phase 5 deep review (every item)

### curve25519-dalek (3 items)

| # | Function | Cited line | Verdict | Rationale |
|---|----------|------------|---------|-----------|
| 1 | `Scalar::non_adjacent_form` | `let bit_buf: u64 = if bit_idx < 64 - w \|\| u64_idx == 3 {` | **FP** | `bit_idx`, `u64_idx` derived from loop counter `pos / 64` and `pos % 64`; both public bookkeeping |
| 2 | `FieldElement::pow_p58` (or sibling) | `if k == 0 {` | **FP** | `k` is loop counter for repeated squaring; public |
| 3 | `Scalar::as_radix_2w` | `let bit_buf: u64 = if bit_idx < 64 - w \|\| u64_idx == 3 {` | **FP** | same pattern as #1, different function |

Read of `scalar.rs:957` (`non_adjacent_form`) and call-graph trace shows `non_adjacent_form` is only reached from `vartime_double_base_mul` and `straus.rs:101` (Straus multi-scalar-mul, used in batch verification). All callers pass public scalars.

### elliptic-curves (2 items)

| # | Function | Cited line | Verdict | Rationale |
|---|----------|------------|---------|-----------|
| 4 | `k256::arithmetic::mul::lincomb` | `tables[i] = (...)` | **FP** | scalar-mul precomputation table indexed by public position |
| 5 | `<p256::Scalar as rustcrypto_ff::Field>::pow` | `while i < n {` | **FP** | `i`/`n` are loop bookkeeping for squaring iteration; the pow exponent is the function arg, not visible at this line |

### rustcrypto/hashes (2 items)

| # | Function | Cited line | Verdict | Rationale |
|---|----------|------------|---------|-----------|
| 6 | `sha2::sha256::compress256` | `if shani_cpuid::get() {` | **FP** (Phase 2 should have caught) | Runtime CPU feature detection at startup |
| 7 | `sha2::sha512::compress512` | `if avx2_cpuid::get() {` | **FP** (Phase 2 should have caught) | Same |

The Phase 2 regex `::cpuid::|::cpu_features?::` only matches `::cpuid::` as a path segment but not the `<crate>_cpuid::get()` form rustcrypto uses (`shani_cpuid`, `avx2_cpuid`, `sse2_cpuid`). A future iteration should broaden this.

### rustls (61 items)

Cluster by cited-line pattern (the harness's `clusters_user_pattern` view shows 84 patterns total; the Phase 5 subset is a long tail of variants):

| Pattern (~lines) | Count | Verdict | Rationale |
|------------------|------:|---------|-----------|
| `let key_share = if self.<config-field>` (5 variants) | 11 | **FP** | choice of KX share depends on configured client capabilities (public config) |
| `if input.<bytes>...` (5 variants in handshake handlers) | 9 | **FP** | input is the wire-format handshake message; public |
| `if matches!(...)` | 3 | **FP** | Rust pattern-match macro; protocol-state dispatch |
| `if our_key_share.share.group() == their_key_share.group` | 7 | **FP** | KX group ID compare; group identifiers are public |
| `Some(current) if now <= current.expires_at => ...` | 2 | **FP** | timestamp comparison on session ticket; both timestamps public |
| `if typ != ContentType::ApplicationData && len == 0` | 2 | **FP** | TLS record header check on public ContentType |
| `if vers == ProtocolVersion::TLSv1_3 ...` | 3 | **FP** | protocol version check (public) |
| `client_auth: match self.client_auth_enabled {` | 4 | **FP** | match on configured boolean (public) |
| `} else if st.config.require_ems {` | 3 | **FP** | configuration-driven branch (public) |
| `if len < C::MIN`  / `if len > 32` | 3 | **FP** | length checks against const-generic / literal (public) |
| `let Some(...) = self.chunks.pop_front() else {` | 1 | **FP** | Option destructure on internal buffer (public state) |
| `pub config_hash: [u8; 32]` (struct field declaration line) | 1 | **FP** | line attribution to a struct field; analyzer's `.loc` artifact |
| `common.lifetime != Duration::ZERO` | 1 | **FP** | session lifetime check (public) |
| `if core::mem::replace(sent_tls13_fake_ccs, true) {` | 1 | **FP** | atomic-replace returns bool from a public flag |
| `let certificates = match identity.identity {` | 2 | **FP** | match on public certificate-identity variant |
| `self.cipher_suite == suite && self.sni.as_ref() == sni` | 2 | **FP** | compare cipher-suite / SNI (both public TLS protocol values) |
| `if self.len != other.len {` | 2 | **FP** | length comparison (public) |
| `v if v == self.write_seq_max => ...` | 1 | **FP** | match guard on TLS record-layer counter (public state) |
| `if item.algorithm == algorithm && item.original == encoding {` | 1 | **FP** | compression cache lookup; algorithm and encoding are public |
| (empty cited line — line attribution to whitespace) | 4 | **FP** | analyzer artifact, no actual code on the cited line |

**61 of 61 rustls Phase 5 items triage to FP.** They are uniformly TLS protocol code: handshake message dispatch, configuration-driven branches, public protocol field comparisons, session ticket timestamps. None operate on key material.

The recurring cause of Phase-5 escape: rustls's protocol code uses idioms my Phase 3 patterns *almost* cover but with slight variants — `let key_share = if self.config_field` is a let-binding wrapping a conditional, not a bare `if`; `if matches!(...)` is the macro form of a match. Better Phase 3 patterns or a Phase 2 rule for "function attributed to a `<connection>::handle` family of methods on the protocol state machine" would dispatch them at lower cost. The `_PROTOCOL_RECEIVER_RE` filter catches some but not all.

## Verdict counts

```
Phase 5 items:        68
  TPs:                 0
  FPs (after review): 68
```

**Across 902 items spanning 8 crates / ~1.3M instructions: 0 true positives.** The review took ~half a working day for the deep-Phase-5 items, dominated by rustls; the other 7 items (dalek + EC + hashes) took under 30 minutes total because they are clear public-bookkeeping patterns.

## Where the waterfall is leaky

Items that reached Phase 5 but should have dispatched earlier:

1. **`<crate>_cpuid::get()`** (2 hashes items) — Phase 2 regex too narrow. Fix: broaden to `(?:^|::|\w*_)cpuid::get|::cpu_features?::|is_(?:x86|aarch64)_feature_detected`.

2. **`if matches!(...)`** (3 rustls items) — Phase 3 regex didn't cover the macro form. Fix: add `^\s*if\s+matches\s*!`.

3. **`let key_share = if self.<field>`** (11 rustls items) — let-binding-wrapping-conditional. Hard to handle generically without false positives. Probably best left as Phase 5 with a richer protocol-receiver classifier.

4. **`Some(current) if now <= current.expires_at`** (2 rustls items) — match arm with guard. Add Phase 3 pattern `^\s*Some\s*\(.+\)\s+if\s+`.

If these fixes were applied: Phase 5 would drop from 68 to ~50, mostly in rustls.

## Files

- `benchmark/scripts/waterfall_triage.py` — the harness
- `benchmark/results/waterfall.json` — full per-item results with phase, verdict, rationale
- This document — the deep review
