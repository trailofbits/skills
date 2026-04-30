# Constant-Time Analysis: Rust

Specialized guidance for analyzing Rust crypto code. The general compiled-language guidance in [compiled.md](compiled.md) still applies; this file documents Rust-specific traps, the analyzer's compiler-flag choices, and what the `subtle` crate buys you.

## Why Rust needs special handling

A naive `rustc --emit=asm crypto.rs` is unreliable for security analysis. Two failure modes are silent and catastrophic:

1. **Constant-folding via `main`.** If the source has `fn main()` calling secret-handling functions with literal arguments, `rustc --crate-type=bin` evaluates the entire chain at compile time and emits no asm for the secret operation. The analyzer reports PASSED on broken crypto. This is a *false negative*, the worst possible outcome for a security tool.

2. **`available_externally` linkage at `opt-level >= 1`.** Even when the file is built as an rlib, LLVM marks unused `pub fn` items as available-externally and skips emitting their bodies. Result: `rustc --emit=asm --crate-type=rlib -C opt-level=2 lib.rs` produces an asm file with *zero* user functions. Again, false negative.

This skill's `RustCompiler` works around both. You don't need to think about the flags; just point the analyzer at a `.rs` file or a Cargo workspace.

## How the analyzer compiles Rust

For a standalone `.rs` file:

```text
rustc --emit=asm                    \
      --crate-type=rlib             \   # never bin, to avoid main-fold DCE
      --crate-name <stem>           \   # so we can filter to user code
      -C opt-level=<O>              \
      -C codegen-units=1            \   # all functions in one asm file
      -C panic=abort                \   # no unwinding noise
      -C debuginfo=1                \   # .file/.loc for source mapping
      -C link-dead-code=on          \   # keep every fn definition
      --edition=2021
```

For a Cargo project (Cargo.toml adjacent), it shells out to:

```bash
RUSTFLAGS="--emit=asm -C codegen-units=1 -C debuginfo=1 -C link-dead-code=on" \
  cargo rustc --release -- -C opt-level=<O>
```

Then it concatenates every `target/<profile>/deps/*.s` file from the user's crate.

## Symbol filtering and demangling

The asm contains user code and any inlined monomorphizations of `core::*`, `alloc::*`, `std::*`, plus support crates (`hashbrown`, `compiler_builtins`, ...). The analyzer:

- Demangles Rust legacy `_ZN…E` symbols to `crate::module::function` form
- Strips the `h<16-hex>` disambiguator
- Drops violations in `RUST_STDLIB_CRATES` by default (use `--include-stdlib` for forensic review)
- For standalone files, restricts to violations in the user's crate (file stem)

You will see violations like:

```text
[ERROR] IDIVL
  Function: kyberslash::compress_paramq_vulnerable
  File: /path/to/src/kyberslash.rs:32
```

The `File:` line comes from the `.loc` directives that `-C debuginfo=1` emits.

## Adopt the `subtle` crate

For comparing/selecting secret values, write `subtle` idioms instead of inventing your own bit-twiddling. The crate is the foundation that `ed25519-dalek`, `curve25519-dalek`, `x25519-dalek`, `ring`, and `RustCrypto` build on.

```rust
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// VULNERABLE: early-exit memcmp leaks tag bytes via timing.
expected == received

// SAFE: ConstantTimeEq is a `volatile_read` + XOR-or-accumulate loop.
expected.ct_eq(received).into()

// VULNERABLE: branch on secret => observable timing.
if cond { a } else { b }

// SAFE: bitmask blend, no branch.
u32::conditional_select(&b, &a, Choice::from(cond as u8))
```

The analyzer treats `subtle::*` as user code (it's not in `RUST_STDLIB_CRATES`); calls into it appear as `callq` to non-flagged routines.

## Warning precision (default-on)

When ERROR-count is zero, every WARN is the entire signal — and noise here is uniquely costly because a reviewer (human or AI) has to reason about each one. The analyzer applies three filters by default to keep WARNs actionable:

1. **`cmp <reg>, $<imm>; jcc` is suppressed.** A branch that follows a compare against a literal is almost always loop control or argument validation on public data. Secrets are rarely compared to small constants. (`test r, r; jz` is treated the same.)
2. **Branches into a panic landing pad are suppressed.** `cmp; jcc <panic-label>` where `<panic-label>` calls `core::panicking::*` is a bounds check or unwrap. The panic path is taken at most once before the program dies — not exploitable as a timing oracle.
3. **Warnings sharing `(file, line, function)` are aggregated.** A single Rust source-level branch (`if`, `for`, `match`) can expand to a dozen asm-level conditional jumps (preamble, body, post-increment, exit edge). Reporting each as a separate warning hides the structural picture. The aggregated form shows the count and the union of mnemonics so you know the source-level event.

Pass `--no-precise-warnings` to disable all three for forensic review of the raw asm.

Real-world impact (libcrux ML-KEM `constant_time_ops.rs`, `--warnings`):
- raw: 11,725 warnings
- with default precision: 297 warnings (97% reduction)

The benchmark corpus enforces these filters do not suppress any of the four CVE-derived vulnerable patterns.

## `--strict` mode

`--strict` promotes warnings to ERRORs when found in functions whose demangled name implies a constant-time contract: `verify*`, `compare*`, `equals*`, `ct_*`, `constant_time_*`, `_in_constant_time`. The premise: if the developer named the function `verify_tag` or `ct_eq`, any branch in it is a regression on its stated contract.

Two guards prevent runaway false positives:
- `--strict` only promotes when the source location is in **user code**. A JNE inside `subtle::ConstantTimeEq::ct_eq` whose source location is `~/.cargo/registry/.../subtle-2.6.1/src/lib.rs:318` (a length check that's part of subtle's public contract) stays a WARN. The same JNE in *your* `src/lib.rs` would become an ERROR.
- The default-on precision filters still apply, so loop counters and panic targets are dropped before promotion.

Use `--strict` in CI for crypto packages; use the default mode for general-purpose codebases.

## Patterns the analyzer flags

### 1. Hardware integer division on a runtime value

```rust
// VULNERABLE: x86_64 emits IDIVL/DIVQ; arm64 emits SDIV/UDIV.
let r = secret % q;          // q is a runtime parameter
let q = secret_nonce / divisor;
```

Flagged on x86_64 / arm64 / arm / riscv64 / ppc64le / s390x / i386. Run with `--arch arm` to see soft-divide calls (`__udivsi3`) on Cortex-M3-class targets.

### 2. Floating-point division and square root

```rust
let p = (a as f64) / (b as f64);   // DIVSD on x86_64
let s = (x as f64).sqrt();          // SQRTSD on x86_64
```

Crypto code shouldn't be using FP at all. If it is, that's a finding in itself — but the FP-DIV/SQRT timing makes it a high-severity finding.

### 3. Secret-dependent branches (with `--warnings`)

```rust
if (exp_bit & 1) == 1 {           // square-and-multiply leak
    result = result * b % m;
}

for &b in tag {                    // early-exit MAC compare
    if b != expected[i] { return false; }
}
```

These compile to `JCC` (x86) / `B.cond` (arm). The analyzer emits warnings, not errors, because branching on public data (lengths, loop bounds) is also unavoidable. Triage each warning by asking *what is the condition?*.

## What the analyzer does not catch

- **Cache-line side channels.** Indexing an array by a secret value (S-box lookup, scalar bit selection) leaks via cache without ever emitting a flagged instruction. Use bit-sliced lookups or constant-time table access primitives.
- **Microarchitectural side channels** (Spectre, Meltdown, MDS). These are dynamic effects.
- **Variable-time runtime helpers.** `u128 % u128` lowers to `__umodti3` (a `callq`), which the analyzer sees as a function call — not a `DIV`. The helper itself is variable-time. Use Montgomery reduction (e.g. `crypto-bigint::BoxedMontyForm`) or a vetted bigint crate.
- **`arm` Cortex-M timing leaks from constant divisors.** Rustc's magic-multiply for `% Q` (with `Q` a const) compiles to `umull`, which is variable-time on Cortex-M4. Pass `--arch arm` and look for `umull` / `smull` in the asm-level review; we don't flag those by default to avoid x86_64 false positives.

## Validating a real-world Rust crate

When auditing a crate that depends on `subtle`/`zeroize`/`elliptic-curve` etc., point the analyzer at the source files of interest:

```bash
# Cargo project (Cargo.toml present):
uv run {baseDir}/ct_analyzer/analyzer.py --warnings src/decryption.rs

# Filter to a single function:
uv run {baseDir}/ct_analyzer/analyzer.py \
    --func 'verify_signature|decapsulate' src/lib.rs

# Cross-arch sweep -- catches Cortex-M-only divisions:
for arch in x86_64 arm64 arm riscv64; do
    uv run {baseDir}/ct_analyzer/analyzer.py --arch $arch src/lib.rs
done
```

Always test at least `--opt-level O0` *and* `--opt-level O3`. `O0` exposes secret divisions that aggressive optimization can fold; `O3` exposes secret branches that smaller opt levels emit redundantly.

## Cargo workspace caveats

For workspace builds, `cargo rustc` only compiles the default member by default. To analyze a specific member, run from the member directory or pass `-p <crate>`:

```bash
# extra flags after `--` are passed to `rustc`; the analyzer adds them.
uv run {baseDir}/ct_analyzer/analyzer.py \
    -X "-p" -X "my_crypto_crate" src/lib.rs
```

For private dependencies in the workspace, a vendored copy in `target/<profile>/deps` is analyzed as if it were stdlib — pass `--include-stdlib` if you need to audit them.

## Benchmark corpus

The repository ships a CVE-derived benchmark at `ct_analyzer/tests/test_samples/rust_bench/`. Each known-vulnerable pattern (KyberSlash, Lucky Thirteen, Minerva, RSA timing) is paired with a constant-time fix. Run the harness to verify the analyzer is still detecting what it should:

```bash
uv run {baseDir}/ct_analyzer/tests/test_samples/rust_bench/run_bench.py
```

A non-zero exit means at least one expectation failed — treat it as a regression.

## `--explain` mode and `triage_hint`

When `ERROR == 0`, every WARN is the entire signal — and a reviewer (human or AI) has to reason about each one. To make that reasoning mechanical rather than guesswork, the analyzer attaches two pieces of metadata to each violation:

1. **`source_snippet`** — five lines of source centered on the cited line, so the reviewer can classify the finding without re-reading the file.
2. **`triage_hint`** — a pre-applied classification using rules A–F documented below. Hints ending in `_likely_fp` can be filed mechanically; hints ending in `_review` need per-line judgment.

CLI: pass `--explain` to surface both in TEXT mode. JSON output always includes them.

```bash
uv run analyzer.py --warnings --explain --json crypto.rs
```

### Triage rules

| Hint                              | Rule                                                       | Verdict |
|-----------------------------------|------------------------------------------------------------|---------|
| `stdlib_iter_end_likely_fp`       | source path matches `core::iter::*`, `core::slice::iter::*`, `core::ops::index_range` | FP — loop iteration on public count |
| `stdlib_bounds_check_likely_fp`   | source path matches `core::slice::mod.rs`                  | FP — bounds check on public length |
| `stdlib_other_likely_fp`          | source path matches `/rustc/.../library/`                  | FP — stdlib internal |
| `dependency_source_review`        | source path matches `~/.cargo/registry/...`                | needs review |
| `fn_declaration_dispatch_likely_fp` | snippet shows a `fn ... <` declaration                   | FP — const-generic dispatch, not real code |
| `user_loop_bound_likely_fp`       | snippet shows `for _ in 0..PUBLIC_CONST`                   | FP — public iteration count |
| `rejection_sample_loop_likely_fp` | snippet shows `while !done` or `while x < UPPER_CONST`     | FP — bound from hash of public seed |
| `compare_to_constant_likely_fp`   | snippet shows comparison against `UPPER_SNAKE_CASE` constant | FP — register-loaded constant |
| `early_return_compare_review`     | snippet shows `if a != b { return ... }` or `return a == b` | needs review — textbook MAC-compare bug |
| `user_code_review`                | snippet readable but no rule fired                         | needs review |
| `needs_review`                    | snippet not readable                                       | needs review |

## Real-world validation

The analyzer has been validated against [Cryspen libcrux](https://github.com/cryspen/libcrux), a formally verified post-quantum crypto library:

- **`libcrux-ml-kem`** (ML-KEM / Kyber): every core file — `ind_cpa.rs`, `ind_cca.rs`, `polynomial.rs`, `ntt.rs`, `sampling.rs`, `constant_time_ops.rs` — passes with **zero ERRORs across 3522 functions / 1.2M instructions**. This includes the IND-CPA and IND-CCA encrypt/decrypt paths and Cryspen's hand-rolled `compare_ciphertexts_in_constant_time` and `select_shared_secret_in_constant_time`.
- **`libcrux-ml-dsa`** (ML-DSA / Dilithium): the analyzer flags one helper, `sample::sample_up_to_four_ring_elements_flat`, at the line `(index / width)`. This is a **true positive** at the instruction level and a **false positive** at the security level: `index` and `width` are the public matrix dimensions of the ML-DSA-44/65/87 parameter set, not secrets. This is exactly the kind of finding the [SKILL.md "Verifying Results" section](../SKILL.md#verifying-results-avoiding-false-positives) tells you to triage. The analyzer is not data-flow-aware; it flags candidate violations and the reviewer confirms whether the operand is secret.

Run it yourself:

```bash
git clone --depth 1 https://github.com/cryspen/libcrux.git /tmp/libcrux
uv run {baseDir}/ct_analyzer/analyzer.py /tmp/libcrux/libcrux-ml-kem/src/ind_cca.rs
uv run {baseDir}/ct_analyzer/analyzer.py /tmp/libcrux/libcrux-ml-dsa/src/sample.rs
```

### Production crate validation

Run against a Cargo project pulling in the most-used Rust crypto crates (`subtle`, `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `aes`, `chacha20poly1305`, `hmac`, `sha2`, `sha3`, `poly1305`):

| Stage                       | Count |
|-----------------------------|------:|
| Raw conditional branches    | 11725+ |
| After precision filters     |    74 |
| After dedup by `(file, line)` |    25 |
| Auto-classified as FP       |    10 |
| Need review                 |    15 (all in dep source) |
| ERRORs                      |     2 (same root finding) |

**The two ERRORs (`DIVQ`/`DIVL` in `cipher::stream::SeekNum::into_block_byte`)** require nuance:

```text
cipher-0.4.4/src/stream.rs:218
        let bs = bs as Self;
        let byte = self % bs;
>       let block = T::try_from(self/bs).map_err(|_| OverflowError)?;
```

This is `SeekNum::into_block_byte`, called from `StreamCipherSeek::try_seek(new_pos)`. Tracing the call chain in `chacha20poly1305-0.10.1/src/cipher.rs:44` shows:

```rust
cipher.seek(BLOCK_SIZE as u64);    // BLOCK_SIZE = 64, compile-time constant
```

In every standard AEAD/streaming-cipher use, the seek operand is a compile-time constant or a public byte offset (file position, disk-block index, etc.). The DIV stays in the asm because rustc fails to specialize the trait method body across the generic boundary, but the operands at every realized call site are public.

**Verdict: latent code smell, not a realized vulnerability.** Using `& (BS - 1)` instead of `% bs` would be cleaner (BS is always a power of 2 for stream ciphers) and would silence the analyzer. If a caller ever passes a secret-derived `seek(secret_offset)`, the DIV would leak — but no such caller exists in any AEAD or streaming flow we audited. This is exactly the kind of finding an instruction-level tool is meant to surface: the structural risk is real, the security verdict requires call-site review, and the reviewer (using `--explain`) can answer it without leaving the report.
