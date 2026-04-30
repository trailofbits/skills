# Wild-Mode Evaluation: Full Production Codebases

We've validated the tuned analyzer on the curated 15-item corpus (P=0.90, R=1.00,
F1=0.95 mechanically — see `MECHANICAL_EVAL.md`). This document scales up: run
the same analyzer against the **entire** built artifact of two production crypto
libraries and triage what comes out.

## Setup

| Library    | Source                | Commit  | Build                           |
|------------|-----------------------|---------|---------------------------------|
| libsodium  | `jedisct1/libsodium`  | HEAD    | `./configure && make` at `-O2 -g` |
| BoringSSL  | `google/boringssl`    | HEAD    | CMake `crypto` target at `-O2 -g` |
| mbedTLS    | `Mbed-TLS/mbedtls`    | HEAD    | `git submodule update --init --recursive --depth=1`, then CMake at `-O2 -g` |

All `git clone --depth=1`.  mbedTLS first attempt failed silently because
the build needs two submodules (`framework`, `tf-psa-crypto`); after
initializing them the build produces 73 `.o` files.

## How the analyzer was driven

The source-level filters (`memcmp-source`, `non-secret`) require standalone-
compilable `.c` files; production codebases don't compile that way. So this
run uses the **already-compiled `.o` files** disassembled with
`objdump -d --no-show-raw-insn`, fed through `analyze_assembly`, and post-
filtered with the asm-only filters (`ct-funcs`, `compiler-helpers`,
`aggregate`).

This is a **strictly weaker** configuration than the curated benchmark — the
two source-level filters are off — so it represents the **lower bound** of
what the tool achieves at scale today.

## What came out

| Library    | .o files | Functions | Instructions | Errors | Warnings | Total | per 1k instr |
|------------|---------:|----------:|-------------:|-------:|---------:|------:|------------:|
| libsodium  |      141 |     1,057 |       77,572 |     12 |      405 |   417 |        5.38 |
| BoringSSL  |      367 |     4,696 |      371,454 |     14 |    2,904 | 2,918 |        7.86 |
| mbedTLS    |       73 |       779 |       64,085 |      8 |      619 |   627 |        9.78 |
| **Total**  |      581 |     6,532 |      513,111 |     34 |    3,928 | 3,962 |        7.72 |

mbedTLS has the **highest finding density of the three** at 9.78 per 1k
instructions. The "0 findings" reading on the first run was a build
artifact (silent submodule failure) - a useful reminder that
`grep -c "Error" build.log` is not a substitute for `ls *.o | wc -l`.

## Mechanical triage of all 34 errors

For the error (DIV / IDIV) class I walked every finding by reading the source.
Spreadsheet-style triage:

### libsodium (12 errors)

| Function                                  | Source location                                 | Verdict   | Why |
|-------------------------------------------|-------------------------------------------------|-----------|-----|
| `_sodium_argon2_fill_segment_avx2`        | `crypto_pwhash/argon2/argon2-fill-block-avx2.c` | FP-public | Argon2 cost params (lanes/passes) are public, not the password |
| `_sodium_argon2_fill_segment_avx512f`     | (avx512f variant)                               | FP-public | same |
| `_sodium_argon2_fill_segment_ref`         | (ref variant)                                   | FP-public | same |
| `_sodium_argon2_ctx`                      | `crypto_pwhash/argon2/argon2.c`                 | FP-public | KDF context init; cost params public |
| `_sodium_argon2_fill_segment_ssse3`       | (ssse3 variant)                                 | FP-public | same |
| `pickparams`                              | `crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c` | FP-public | scrypt N/r/p are public cost knobs |
| `_sodium_escrypt_kdf_nosse`               | (nosse variant)                                 | FP-public | scrypt cost params public |
| `_sodium_escrypt_kdf_sse`                 | (sse variant)                                   | FP-public | same |
| `randombytes_uniform`                     | `randombytes/randombytes.c`                     | FP-public | `(2^32 - upper) % upper`; `upper` is the public range argument |
| `ip_write_num`                            | `sodium/codecs.c`                               | FP-public | decimal digit codec; not crypto |
| `sodium_allocarray`                       | `sodium/utils.c`                                | FP-public | `count * size` overflow check on public sizes |
| `sodium_pad`                              | `sodium/utils.c`                                | FP-public | `unpadded_len % blocksize`; blocksize is public |

### BoringSSL (14 errors)

| Function                                     | Source location                                       | Verdict | Why |
|----------------------------------------------|-------------------------------------------------------|---------|-----|
| `BN_mod_exp_mont_word`                       | `crypto/fipsmodule/bn/exponentiation.cc.inc`          | FP-public | DIV is on public bit-length / sizeof, not the exponent |
| `EVP_PBE_scrypt`                             | `crypto/evp_extra/scrypt.cc.inc`                      | FP-public | scrypt cost params public |
| `OPENSSL_lh_retrieve` / `_retrieve_key`      | `crypto/lhash/lhash.cc.inc`                           | FP-public | hash-table modulo on public table size; not on key material |
| `OPENSSL_lh_insert` / `_delete` / `_doall_arg` | (same)                                              | FP-public | same |
| `pkcs12_key_gen`                             | `crypto/pkcs8/pkcs8.cc.inc`                           | FP-public | PKCS#12 KDF: iterations + key length are public |
| `std::__rotate<void**>`                      | libc++ template instantiation                         | FP-public | not crypto code |
| `bn_mod_u16_consttime`                       | `crypto/fipsmodule/bn/div_extra.cc.inc:65`            | FP-doc    | source comment says **"this operation is not constant-time, but `p` and `d` are public values"** |
| `BN_mod_exp_mont_consttime`                  | `crypto/fipsmodule/bn/exponentiation.cc.inc:259, 502` | FP-public | bound checks `INT_MAX / sizeof(...)`; secret exponent is never the divisor |
| `BN_div_word`                                | `crypto/fipsmodule/bn/div.cc.inc`                     | FP-doc    | documented variable-time helper; "callers must not pass secret divisors" |
| `BN_div.part.0`                              | (same file)                                           | FP-doc    | same |
| `HKDF_expand`                                | `crypto/fipsmodule/hkdf/hkdf.cc.inc`                  | FP-public | output length / blocks-needed is public |

### mbedTLS (8 errors)

| Function                              | Source location                                    | Verdict | Why |
|---------------------------------------|----------------------------------------------------|---------|-----|
| `mbedtls_mpi_mod_int`                 | `bignum.c:1593` (`y / b` and `z * b - y`)         | **TP**  | Variable-time DIV inside the function body.  Documented variable-time, but **callers in `bignum.c:2109` and `:2324` invoke it during prime-generation sieving** where the dividend `A` is a secret prime candidate.  Reachable timing leak in keygen. |
| `mbedtls_cipher_update`               | `cipher.c:483` (`ilen % block_size`)              | FP-public | both operands public |
| `mbedtls_cipher_cmac_update`          | `cmac.c:227` (`(ilen + block_size - 1) / block_size`) | FP-public | same |
| `ecp_mul_restartable_internal.isra.0` | `ecp.c:1815` (`j / d`) and `:2205` (`(grp->nbits + w-1) / w`) | FP-public | window size and curve bit-length are public |
| `mbedtls_psa_cipher_update`           | wrapper around `cipher_update`                     | FP-public | same |
| `mbedtls_sha3_update`                 | `sha3.c:359` (`(idx+1) % max_block_size`)         | FP-public | block size public, idx tracks public byte position |
| `mbedtls_sha3_finish`                 | `sha3.c` (similar pattern)                         | FP-public | same |
| `mbedtls_pkcs5_pbes2_ext`             | `pkcs5.c` (PBKDF2 iteration / key-length math)    | FP-public | iter count, key length public |

### Error tally

| Verdict   | Count | Notes |
|-----------|------:|-------|
| **TP**    | **1** | mbedtls_mpi_mod_int reachable from RSA prime-gen sieve |
| FP-public |    30 | Divisor traces back to a public sizing parameter |
| FP-doc    |     3 | Function is documented as variable-time on purpose |
| **Total** | **34** | **Precision_errors = 1/34 = 0.029** |

The single TP is informative: it took adding mbedTLS - which we initially
miscounted as zero - to find any signal at all. The libsodium and BoringSSL
DIV class is genuinely public-only; mbedTLS exposes a documented variable-
time helper that is wired into a secret-handling path. Whether this is a
practically exploitable leak (RSA keygen happens once per identity, network
timing is harder) is a separate question; as a static-analysis flag, it is
correct.

## Stratified sample of warnings (n=30)

I drew a random sample of 30 warnings (seeded for reproducibility) from the
3,309-warning pool and walked each:

| #   | Lib       | Mnem | Function                                  | Verdict   | Why |
|-----|-----------|------|-------------------------------------------|-----------|-----|
|  1  | boringssl | JLE  | `BN_is_odd`                               | FP-public | `width < 1` bound check on the BIGNUM |
|  2  | boringssl | JE   | `asn1_marshal_object`                     | FP-public | DER encoding; format-driven |
|  3  | libsodium | JNE  | `ristretto255_elligator`                  | FP-loop   | hash-to-curve loop counter |
|  4  | boringssl | JA   | `CTR_DRBG_generate`                       | FP-public | output-length loop bound |
|  5  | boringssl | JE   | `EVP_PKEY_verify_recover_init`            | FP-public | parameter setup |
|  6  | boringssl | JE   | `ec_hash_to_scalar_p384_xmd_sha384`       | FP-loop   | XMD output-block counter |
|  7  | boringssl | JE   | `md4_init`                                | FP-public | hash-state init |
|  8  | boringssl | JE   | `BIO_gets`                                | FP-public | I/O wrapper, not crypto |
|  9  | boringssl | JNE  | `BCM_mldsa44_marshal_public_key`          | FP-public | marshalling **public** key |
| 10  | boringssl | JS   | `d2i_ASN1_BOOLEAN`                        | FP-public | DER decoder |
| 11  | boringssl | JE   | `AES_CMAC`                                | FP-loop   | block-loop counter |
| 12  | boringssl | JE   | `CTR_DRBG_free`                           | FP-public | cleanup |
| 13  | boringssl | JE   | `d2i_RSAPublicKey_fp`                     | FP-public | public-key decoder |
| 14  | libsodium | JE   | `turboshake256_ref_squeeze`               | FP-loop   | output-length loop bound |
| 15  | boringssl | JNE  | `gcm_polyval_nohw`                        | FP-loop   | block-multiply loop counter |
| 16  | boringssl | JE   | `sk_pop_free`                             | FP-public | stack management |
| 17  | libsodium | JNE  | `softaes_invert_key_schedule256`          | FP-loop   | round counter (14 rounds, public) |
| 18  | libsodium | JE   | `crypto_core_hchacha20`                   | FP-loop   | block-bound loop |
| 19  | libsodium | JBE  | `sodium_bin2ip`                           | FP-public | IP-address text codec |
| 20  | boringssl | JE   | `DES_set_key_ex`                          | FP-loop   | DES round-key counter |
| 21  | boringssl | JE   | `DSA_dup_DH`                              | FP-public | parameter copy |
| 22  | boringssl | JE   | `X509_NAME_hash`                          | FP-public | name hashing for cert lookup |
| 23  | boringssl | JE   | `ecp_nistz256_points_mul_public`          | FP-loop   | scalar-mul on **public** scalar (function name says it!) |
| 24  | libsodium | JNE  | `ge25519_tobytes`                         | FP-loop   | limb-loop counter |
| 25  | boringssl | JE   | `X509_NAME_ENTRY_new`                     | FP-public | allocator |
| 26  | boringssl | JE   | `calc_tag_pre`                            | FP-loop   | Poly1305/GCM block counter |
| 27  | boringssl | JNE  | `mldsa::scalar_uniform<2>`                | FP-public | rejection sample of **public** matrix A from `rho` |
| 28  | boringssl | JBE  | `ec_GFp_mont_init_precomp`                | FP-public | precomp setup; uses public group params |
| 29  | boringssl | JAE  | `ec_GFp_mont_mul_precomp`                 | FP-loop   | precomp loop bound |
| 30  | boringssl | JE   | `i2d_RSAPrivateKey_fp`                    | FP-public | DER structure encoding (key bytes are written but the BRANCH is on public DER lengths) |

| Verdict      | Count |
|--------------|------:|
| FP-public    |    16 |
| FP-loop      |    14 |
| **TP**       |   **0** |

**Precision_warnings (sample) = 0/30 = 0.000 (95% CI ~ [0, 0.116])**

A separate sample of 20 mbedTLS warnings (seed=42) was triaged:

| Verdict      | Count |
|--------------|------:|
| FP-public    |    13 |
| FP-loop      |     7 |
| **TP**       |   **0** |

Notable: two of the sampled functions are explicitly named for CT
intent - `mbedtls_mpi_safe_cond_assign` and `mbedtls_mpi_lt_mpi_ct` -
and would be silenced by extending the `ct-funcs` allowlist with
patterns like `^mbedtls_mpi_.*_ct$` and `^mbedtls_mpi_safe_.*$`.

Extrapolating from 50 sampled warnings (out of 3,928): expected TP count
is somewhere in [0, ~470] under a 95% binomial CI; concretely, the next
3,878 unexamined warnings would need a TP rate of ~12% before changing
the headline. We saw 0 in 50 - the rate is almost certainly very low.

## Headline numbers (wild)

| Quantity                | Value |
|-------------------------|------:|
| Total findings          | 3,962 |
| Findings triaged        |    84 (all 34 errors + 50 sampled warnings) |
| TPs (mechanical)        |     1 (mbedtls_mpi_mod_int) |
| FPs (mechanical)        |    83 |
| **Precision (full sample)** | **1/84 = 0.012** |
| Recall                  | undefined as a ratio (no documented timing CVE at HEAD); the one TP we found was not in any pre-known list, so the tool is *adding* signal here |
| Triage time (full corpus) | 34 errors x ~3 min + 3,928 warnings x ~2 min = **~133 hours** of expert effort |
| Triage time (this eval) | 34 errors + 50 sampled warnings ~= **3 hours** of expert effort |

## Why the wild precision collapses (and how to fix it)

The curated-corpus benchmark hit P=0.90, F1=0.95. The wild run on the same
analyzer hits P~0 on the sampled findings. Three reasons explain the gap, all
fixable:

1. **The two source-level filters could not run.** `memcmp-source` and
   `non-secret` together account for ~70% of the precision gain in the
   curated benchmark. They need the `.c` source path; the wild run had only
   `.o` files. Mapping `.o` to its source via the DWARF debug info (`addr2line`,
   `objdump --dwarf=decodedline`) and then invoking those filters per finding
   would close most of the gap. Estimated impact: P would rise from ~0 to
   ~0.5-0.7.

2. **The `ct-funcs` allowlist is corpus-shaped, not codebase-shaped.**
   It currently matches BoringSSL's `constant_time_select_w`, libsodium's
   `sodium_memcmp`, etc. - because the curated corpus contains those by
   name. Production code introduces hundreds more CT primitives:
   `gcm_polyval_*`, `ec_GFp_mont_*`, `BCM_mldsa*_marshal_*`, the `ge25519_*`
   family, `_sodium_softaes_*` round functions. A practical CI workflow
   would maintain a per-repo `.ct-allowlist` of vetted function-name patterns
   that ride alongside the source. Estimated impact: P would rise another
   0.1-0.2.

3. **The error class doesn't carry source-context.** Every one of the 26
   DIV/IDIV findings is on a public sizing parameter (`% blocksize`,
   `INT_MAX / sizeof`, `count * size` overflow checks, hash-table modulo).
   A simple operand-aware analysis - "is the divisor an immediate constant
   loaded from `mov $K, %reg` immediately preceding?" - would catch all
   12 libsodium errors and at least 8 of the 14 BoringSSL ones. Estimated
   impact: error-class precision goes from 0/26 to ~0.7-0.9.

## What this evaluation tells us

- **The tool is precision-good in its benchmark sweet-spot (curated source
  files, all filters armed) and precision-collapses in its current weakest
  configuration (asm-only, no source).** The CT-AFI metric we built measures
  the former; it doesn't capture the latter, which is the deployment scenario
  at scale.

- **Recall on production code looks fine** in the sense that there are no
  documented timing CVEs at HEAD on either libsodium or BoringSSL, and the
  tool flagged 0 real issues - so 0 missed.  Saying "recall is 1.0" though
  is meaningless when TP=0; the better statement is **"the libraries are
  CT-clean and the tool agrees by way of a 100% noise-bound."**

- **Closing the wild precision gap is engineering, not research.** Source-
  attribution via DWARF + per-codebase allowlists + a divisor-source
  heuristic should bring wild precision into the 0.5-0.8 range without
  affecting the curated-benchmark numbers. That's the next iteration.

## Reproducing this run

```bash
cd plugins/constant-time-analysis
mkdir -p benchmark/wild && cd benchmark/wild

git clone --depth=1 https://github.com/jedisct1/libsodium.git
git clone --depth=1 https://github.com/google/boringssl.git

# libsodium
(cd libsodium && ./autogen.sh -s && \
  ./configure --disable-shared --enable-static CFLAGS="-O2 -g -fPIC" && \
  make -j$(nproc))

# BoringSSL
(cd boringssl && cmake -S . -B build -DCMAKE_C_FLAGS="-O2 -g" \
   -DCMAKE_CXX_FLAGS="-O2 -g" -DCMAKE_BUILD_TYPE=Release && \
  cmake --build build --target crypto -j$(nproc))

# Analyze
cd ../..
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild/libsodium --label libsodium \
  --out benchmark/results/wild_libsodium.json
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild/boringssl/build --label boringssl \
  --out benchmark/results/wild_boringssl.json
```
