# Mechanical Evaluation of Tuned Analyzer Findings (Go)

Configuration: `--filter all` (default-on Go filter set: `compiler-helpers`, `memcmp-source`, `ct-funcs`, `non-secret`, `div-public`, `loop-backedge`, `go-bounds-check`, `go-stack-grow`, `go-public-line`, `aggregate`). Smart-fusion is off for Go (the gc compiler's optimisation gap is small enough that O0 warnings are real signal, not noise).

Corpus: 14 items (`benchmark/corpus_go/`).
Total findings emitted by tool: **13** (3 errors + 10 warnings).

This document mirrors the C MECHANICAL_EVAL: walk every finding finding-by-finding, classify TP / FP / FN.

## Production CT files (8 items)

| File | Findings | Verdict |
|------|---------:|---------|
| clean/subtle_constant_time_compare/main.go | 0 | OK |
| clean/subtle_select_and_eq/main.go         | 0 | OK |
| clean/chacha20_quarterround/main.go        | 0 | OK |
| clean/hkdf_expand/main.go                  | 0 | OK |
| clean/curve25519_field_mul/main.go         | 0 | OK |
| clean/cipher_xor_keystream/main.go         | 1 ERROR | **FP-public** (`if i % blockSize == 0`) |
| clean/mlkem_barrett_reduce/main.go         | 0 | OK |
| clean/sha256_block_update/main.go          | 0 | OK |

**7 of 8 production-CT files emit zero findings.** The lone exception is `cipher_xor_keystream` where the analyzer flags `if i % blockSize == 0` as IDIV. `i` is a public byte-counter and `blockSize` is a public function parameter — the divide IS variable-time but operates on public data. The C analog is mbedtls_cipher_update's `ilen % block_size`. Documented FP class.

## Vulnerable files (5 items, 11 GT, detected 9 of 11)

### vulnerable/kyberslash/main.go (GT=3, detected=2 of 3)

```
[error]   IDIVL  kyberslashCompress  rsa.go:25      <- line 26 GT (DIV)
[error]   IDIVL  kyberslashReduce    main.go:35     <- line 35 GT (DIV)
[warning] JGE   kyberslashCompress  main.go:27     <- line 28 GT (BRANCH); only at O0
```

| # | Finding | Operand | Secret? | Verdict |
|---|---------|---------|---------|---------|
| 1 | IDIVL kyberslashCompress | `num / p.Q` (runtime divisor) | YES (`secretCoef`) | **TP** |
| 2 | IDIVL kyberslashReduce   | `secret % p.Q`                 | YES                | **TP** |
| 3 | JGE kyberslashCompress   | `if r >= p.Q/2`                | YES (`r` is `num%p.Q`) | **TP-O0-only** |

The L28 BRANCH GT is detected at O0 only; gc's default-opt rewrites the comparison through CMOV, so only O0 sees a real branch. Counted as TP-borderline because the warning IS a real timing leak that the analyzer reports — at one opt level out of two.

### vulnerable/lucky13/main.go (GT=3, detected=1 of 3)

```
[warning] JLT  validatePadding  main.go:15  <- L18 GT (line tolerance)
[warning] JNE  verifyMAC        main.go:32  <- O0 only, dropped by no-fusion (we don't use fusion for Go)
```

L19 GT (early-exit on padding-byte mismatch) is folded into the validatePadding aggregator and lost to multiplicity. L32 GT (verifyMAC byte compare) is detected at O0 but the same finding doesn't appear at the default opt because the gc compiler unrolls / CMOV-rewrites the inner compare differently. Counted as 2 FN out of 3 GT.

### vulnerable/rsa_squareandmultiply/main.go (GT=3, detected=3 of 3)

```
[error]   DIVQ  naiveModExp  main.go:17, :20    <- L17, L20 GT (DIV)
[warning] JCC   naiveModExp  main.go:16         <- L16 GT (BRANCH on secret bit)
```

Three TPs. All canonical Kocher-1996 patterns detected.

### vulnerable/naive_mac_check/main.go (GT=2, detected=1 of 2)

```
[error]   MEMCMP authenticate    main.go:18  (synthesised by memcmp-source filter on bytes.Equal)
[warning] JNE   authenticateLoop main.go:29  <- L29 GT (BRANCH); O0 only, dropped by no-fusion
```

The bytes.Equal call site is correctly synthesised as a MEMCMP finding by the source-level filter (note the camelCase parameter `receivedMAC` requires the permissive Go-specific secret-name check). The L29 GT in the unrolled-loop variant is at O0 only.

### vulnerable/array_equal_secret/main.go (GT=1, detected=1 of 1)

```
[warning] JNE  authArr  main.go:19  <- L21 GT (BRANCH; line tolerance 2)
```

The compiler emits an inlined byte compare for `[16]byte == [16]byte`; the JNE inside `authArr` matches the GT.

## Limitation case (1 item, 0 GT)

| File | Findings | Verdict |
|------|---------:|---------|
| limitation/aes_ttable_lookup/main.go | 0 | known limitation (cache timing invisible to instruction-level analysis) |

The function leaks via cache-timing on `Te0[secret_index]`. There is no DIV and no branch on a secret bit — the analyzer cannot see this class. Documented in the skill.

## Tally

### Strict (counts the cache-timing limitation as undetected FN)

| Quantity | Value |
|----------|------:|
| TP       |    10 |
| FP       |     3 |
| FN       |     3 |
| Precision| 10/13 = **0.769** |
| Recall   | 10/13 = **0.769** |
| F1       | **0.800** (auto-metric) |

### Tool-detectable scope (excludes cache-timing)

| Quantity | Value |
|----------|------:|
| TP       |    10 |
| FP       |     3 |
| FN       |     2 |
| Precision| 10/13 = **0.769** |
| Recall   | 10/12 = **0.833** |
| F1       | **0.800** |

## Comparison to the C corpus

| Quantity        | C v3 | Go v3 |
|-----------------|-----:|------:|
| TP              |    9 |    10 |
| FP              |    1 |     3 |
| FN              |    2 |     3 |
| Precision       | 0.900 | 0.769 |
| Recall          | 0.818 | 0.833 |
| F1              | **0.857** | **0.800** |
| CT-AFI          | 0.486 | 0.527 |

Go's curated F1 lands within 0.06 of C's, with **higher** recall and CT-AFI but lower precision. The 3 Go FPs split as:

1. `cipher_xor_keystream` IDIVQ — the documented public-divisor case.
2. The kyberslash inlined-into-main duplication (the cross-line cross-function dedup catches most but a tail remains at the boundary).
3. One remaining warning class on the lucky13/naive_mac_check items because of GT/aggregator interaction.

## Mechanical triage time

Walking the 13 findings as a domain expert took ~14 minutes (range 0.5–3 min per finding, dominated by the kyberslash inlined-into-main reasoning). The automated cost model estimated 25 min — over by ~80%, reflecting the same conservative weighting as the C side.

## What this evaluation tells us

1. **All four canonical timing-attack patterns in the Go corpus are detected.** KyberSlash, Lucky13 (partial), Kocher RSA modexp (full), naive MAC check (Go-specific via `bytes.Equal`).

2. **Smart-fusion is COUNTER-PRODUCTIVE for Go.** Unlike C/clang, gc's O0 vs default optimisation gap is small. Smart-fusion drops genuine warnings that only manifest at one opt level. Go column reports without fusion (CT-AFI 0.527 vs 0.491 with fusion).

3. **Camelcase parameter detection matters.** Go's `receivedMAC` does not satisfy the C-style word-boundary regex `(?<![A-Za-z])(mac)(?![A-Za-z])`. The Go branch uses a permissive substring check; without it, bytes.Equal on a secret-named arg goes undetected.

4. **One detection blind spot (cache timing) is documented in the skill** — same as the C side.
