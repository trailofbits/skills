# v3: DWARF Source Attribution (the missing piece)

The user pointed out that v1/v2 were leaving signal on the table - we had
already compiled with `-g`, which means every `.o` carried full DWARF
debug info that could attribute every instruction back to a `.c` file
and line number.  v3 actually wires this through.

## What was missing in v2

The wild benchmark harness did:

```python
subprocess.check_output(["objdump", "-d", "--no-show-raw-insn", str(obj)])
```

Note the **missing `-l` flag**.  `objdump -l` emits source attributions
as standalone lines like:

```
/abs/path/to/bignum.c:1593
    2bb7:    lea    -0x1(%rsi,%r13,1),%rax
```

The analyzer's parser already had a regex for `# file:NN` style comments
from `gcc -S` output, but didn't recognize objdump's bare-path format.
And the source-level filters (`memcmp-source`, `non-secret`) were
hard-wired to a single `source_path` argument, not a per-finding lookup.

So all the data was sitting in the `.o` files, unused.

## The fix (3 changes)

1. `run_wild.py` calls `objdump -d -l --no-show-raw-insn` (added `-l`).
2. `analyzer.py:AssemblyParser.parse` recognizes objdump's
   `/abs/path.c:NN[ (discriminator N)]` line markers and stamps every
   subsequent violation with `v.file` / `v.line`.
3. `filters.py:apply_filters` consumes `v.file` per-finding when no
   global `source_path` was given, caching parsed sources by path so
   one wild scan over libsodium doesn't re-parse `utils.c` 50 times.

Two follow-on bugs found and fixed:

- The `non-secret` filter was rolled back to suppress only WARNINGS.
  The v2 extension to errors made it kill `mbedtls_mpi_mod_int` (the
  one wild TP), whose source params are named `r, A, b` - none match
  the secret-token regex.  In production, a documented variable-time
  helper called from a secret-handling context still deserves an ERROR
  flag; only the WARNING class can be safely gated by parameter naming.
- The new function-range tracker had an infinite loop on functions
  whose closing `}` was on a line without `{` (which is most of them).
  Brace-depth tracking now properly handles all-close lines.

## Numbers (curated, must not regress)

|         | v1     | v2     | v3     |
|---------|-------:|-------:|-------:|
| Curated F1 | 0.857 | 0.857 | 0.857 |
| Curated CT-AFI | 0.486 | 0.486 | 0.486 |

Held-out check: zero regression across all three versions.

## Numbers (wild)

| Library    | v1 total | v2 total | v3 total | v1->v3   |
|------------|---------:|---------:|---------:|---------:|
| libsodium  |      417 |      337 |       69 |   -83.5% |
| mbedTLS    |      627 |      382 |      108 |   -82.8% |
| BoringSSL  |    2,918 |    2,109 |      116 |   -96.0% |
| **Total**  |  **3,962** |  **2,828** |    **293** | **-92.6%** |

| Wild error class | v1 | v2 | v3 |
|------------------|---:|---:|---:|
| Errors           | 34 |  2 |  2 |
| TPs preserved    |  1 |  1 |  1 |
| FP rate (errors) | 0.971 | 0.500 | **0.500** |

| Triage cost (full corpus) | v1     | v2    | v3    |
|---------------------------|-------:|------:|------:|
| Errors @ 3 min            | 102 min | 6 min | 6 min |
| Warnings @ 2 min          | 7,856 min | 5,652 min | 582 min |
| **Total**                 | **~133 hr** | **~94 hr** | **~9.8 hr** |

The total triage budget collapsed from 133 hours (v1) to 9.8 hours (v3).
That's the headline.  The mbedTLS TP is still found, and the absolute
finding rate per 1k instructions dropped from 7.7 to ~0.6.

## v3 mechanical triage

### 2 errors (full enumeration)

| Function                              | Source          | Verdict | Why |
|---------------------------------------|-----------------|---------|-----|
| `mbedtls_mpi_mod_int`                 | bignum.c:1601   | TP      | Variable-time DIV reachable from RSA prime-gen sieve (preserved across v1/v2/v3) |
| `ecp_mul_restartable_internal.isra.0` | ecp.c:2205      | FP-public | `(grp->nbits + w-1) / w`; both operands are public curve params |

### 30 held-out warnings (seed=44, distinct from v1's 42 / v2's 43)

All 30 came back FP-public.  No TPs surfaced in the random sample.
Selected pattern breakdown (function-name discovery is now reliable
because of DWARF):

| Pattern                              | Count | Example |
|--------------------------------------|------:|---------|
| AEAD encrypt/decrypt entry-points    |     6 | `crypto_aead_aes256gcm_*`, `mbedtls_ccm_auth_decrypt` |
| KDF / pwhash wrappers                |     6 | `crypto_pwhash`, `EVP_BytesToKey`, `crypto_kdf_hkdf_sha512_extract` |
| DER/PEM serialization                |     5 | `PEM_write_*`, `mbedtls_pk_write_*`, `CBS_get_asn1` |
| Sign / verify / keygen wrappers      |     5 | `ED25519_sign`, `DSA_verify`, `mbedtls_lms_verify`, `mbedtls_psa_ecp_generate_key` |
| Type-check / dispatch                |     4 | `mbedtls_pk_import_into_psa`, `copy_from_psa`, `OBJ_find_sigid_by_algs` |
| Length / size accessors              |     2 | `ECDSA_size` |
| ML-KEM noise sampling (public seed)  |     1 | `poly_getnoise_eta2` |
| Cipher wrapper                       |     1 | `mbedtls_chacha20_crypt` |

| Verdict      | Count |
|--------------|------:|
| TP           |     0 |
| FP-public    |    30 |
| FP-loop      |     0 |

The loop-backedge filter from v2 caught essentially all the loop-counter
warnings that dominated the sample noise in earlier runs.  What remains
in v3 is "public-protocol code that branches on length/type/bool".
Those need a structural analysis (e.g., "this branch is the last
conditional before `ret`, on the function's own return value") rather
than a name pattern.

## Lessons (v3 vs v1/v2)

1. **The "engineering vs research" split was wrong.**  I called source
   attribution "engineering work this loop didn't have time for" - it was
   one missing flag (`objdump -l`) and ~80 lines of plumbing.  Estimated
   impact in V2_DESIGN was 0 -> 0.5-0.7 wild precision.  Actual: warning
   count dropped 90% (4,000 -> 290), triage time 133hr -> 10hr.  When
   the data is right there in the build output, "engineering" is a small
   fraction of the value the change unlocks.

2. **Each design iteration finds a regression.**  v2 had an over-broad
   `_validate_*` pattern that killed Lucky13.  v3 had an over-broad
   non-secret extension that killed mbedtls_mpi_mod_int.  v3 also
   shipped initially with an infinite loop in the function-range
   tracker.  The curated benchmark caught 2 of the 3 before commit;
   the third (infinite loop) showed up as a hang and got fixed in
   the same session.  The implication is the same: **always run the
   curated regression check after every filter change**, and have a
   timeout in the test harness so a hang fails fast instead of dragging.

3. **DWARF is part of the build product.**  We compile with `-g` for
   exactly this reason.  Any analyzer running on `.o` files that doesn't
   consume the DWARF info is leaving 90% of its potential precision on
   the floor.  This is now a one-liner (`objdump -l`) plus one regex.

## What v3 didn't fix

- The Montgomery-window-size DIV in `ecp_mul_restartable_internal.isra.0`
  still flags as an error.  Catching it requires symbolic backtracking
  (the divisor `d` is computed from public curve params via several
  intermediate registers), which the linear context-walk in `div-public`
  can't do.

- The 291 remaining warnings are a long tail of public-protocol code.
  Closing that needs a "branches on the function's return value" filter,
  or a per-codebase allowlist file.  Both are useful follow-ups; neither
  is in v3.

- BoringSSL's mangled C++ symbol names (`_ZN4bssl...`) don't always demangle
  to clean function names; the allowlist needs a few more symbol-shape
  patterns to handle the long tail.

## Reproducing v3

```bash
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild/libsodium --label libsodium_v3 \
  --out benchmark/results/wild_libsodium_v3.json
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild/mbedtls/build --label mbedtls_v3 \
  --out benchmark/results/wild_mbedtls_v3.json
PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
  --root benchmark/wild/boringssl/build --label boringssl_v3 \
  --out benchmark/results/wild_boringssl_v3.json
```

The default filter set (`ct-funcs,compiler-helpers,div-public,loop-backedge,memcmp-source,non-secret,aggregate`) is the v3 configuration.
