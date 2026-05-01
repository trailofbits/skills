# Lessons Learned (BLS12-381 Case Study)

Patterns observed during mutation testing of gnark-crypto (Go),
blst (Rust FFI), and zkcrypto/bls12_381 (Rust):

## 1. FFI Wrappers Have 0% Kill Rate

Mutating blst's Rust bindings produced 0 kills across 79 mutants.
The Rust layer is thin wrappers around C/assembly — mutations to
`PartialEq`, `miller_loop_n`, `finalverify` all survive because
the real logic is in C. **Always identify FFI crates in Phase 1
and skip them for Rust/Go mutation testing. Use Mull for the C layer.**

## 2. Timeouts Mask Surviving Mutants

Adding Wycheproof tests to gnark-crypto changed gremlins' timeout
calibration, converting 3,144 timeouts into 2,533 killed + 476
lived. The 476 LIVED mutants were previously hidden. **Always
resolve timeouts before comparing baselines. Increase timeout
coefficients (`--timeout-coefficient 3`) for the first run.**

## 3. Cross-Package NOT COVERED ≠ Dead Code

In gnark-crypto, `hash_to_curve/g2.go` functions appeared as NOT
COVERED even though `HashToG2()` in the parent package calls them.
Gremlins only runs same-package tests for each mutated file.
**Use the call graph to identify cross-package false positives
before generating vectors for NOT COVERED mutants.**

## 4. Comprehensive Test Suites Resist Vector Coverage

gnark-crypto's own test suite already kills every mutant that
Wycheproof vectors can reach. The 53 NOT COVERED BLS mutants are
identical between baseline and Wycheproof runs. **The value of
Wycheproof vectors for well-tested libraries is cross-implementation
semantic validation, not code coverage improvement.**

## 5. Bitwise Operator Mutations Reveal Precision Gaps

In zkcrypto, 164 mutants survived — mostly `&` → `|` and `|` → `^`
in field arithmetic (`Fp::square`, `Fp::neg`, `Scalar::ct_eq`).
These mutations corrupt specific bits in multi-precision arithmetic.
**Killing bitwise mutations requires test vectors that exercise
every limb of the field representation, not just the "happy path"
with small values.** Vectors needed:
- Field element = modulus - 1 (all limbs active)
- Field element with alternating 0/1 limb patterns
- Scalar values near the group order boundary

## 6. Security-Critical Mutations Need Priority

`Scalar::ct_eq` with `&` → `|` makes equality permissive — more
values compare as equal. This could cause signature verification
to accept invalid signatures. **Always prioritize mutations in
equality checks, validation logic, and authentication paths.**

## 7. Test Harnesses Must Assert Rejection, Not Just Acceptance

The initial zkcrypto Wycheproof harness only checked that valid
vectors deserialized successfully. It never checked that invalid
vectors were *rejected*. This meant all flag-permissive mutations
(`&` → `|` in `from_compressed_unchecked`) survived — the mutated
code accepted invalid flags, but no test asserted rejection.

Adding `else if result == "invalid" { assert!(deser.is_none()) }`
killed ALL P1 flag mutations in both G1 and G2. **Every test
harness needs both positive assertions (valid accepted) AND
negative assertions (invalid rejected). Without negative
assertions, permissive mutations are invisible.**

## 8. Roundtrip Assertions Catch Field Arithmetic Corruption

`compress(decompress(bytes)) == bytes` is a powerful generic
assertion that catches carry propagation, square root, negation,
and modular reduction bugs without knowing the internal field
representation. If `Fp::square` or `Fp::subtract_p` has a carry
bug, the recovered y-coordinate will be wrong, changing the sort
bit in the re-compressed encoding.

This killed 15 previously-missed fp.rs mutations. **Add roundtrip
assertions to every deserialization test that handles valid
vectors. It's cheap and catches deep arithmetic bugs.**

## 9. Equivalent Mutant Pattern: Shift-then-OR

In `Fp::square` and `Scalar::square`, the doubling step uses
`(t << 1) | (prev >> 63)`. The mutation `|` → `^` survives
because `(t << 1)` always clears bit 0 (left shift), and
`(prev >> 63)` only affects bit 0. Since `0 | x == 0 ^ x` for
any `x`, these mutations are provably equivalent — they cannot
change behavior regardless of input.

14 of the "survived" mutations across scalar.rs and fp.rs are
this pattern. **When triaging `|` → `^` mutations in shift-based
expressions, check if the OR'd bit position is always 0 after the
shift. If so, classify as equivalent and skip.**

## 10. Montgomery Representation Creates an API Testing Boundary

`Scalar::ct_eq` computes `limb[0].ct_eq & limb[1].ct_eq & ...`.
With `&` → `|`, it returns equal if ANY limb matches. To kill
this, you need two different scalars that share at least one
internal Montgomery limb value. But `Scalar::from_raw` applies
Montgomery reduction (multiply by R), spreading the value across
all limbs unpredictably.

You cannot construct Montgomery-limb-aware test values through the
public API. **Mutations in internal representation comparisons
(ct_eq on limb arrays) require library-internal property-based
tests, not external test vectors. Document these as "not reachable
via API" rather than wasting time on vector design.**

## 11. Single-Fault Negative Vectors Isolate Validation Checks

The most effective flag vectors had exactly ONE defect — e.g.,
a valid G2 point with only the compression flag cleared. This
isolates the specific flag check: if `from_compressed` accepts
the vector, that particular validation is broken.

Multi-fault vectors (wrong flag AND wrong length AND off-curve)
are less useful because multiple checks reject them — you can't
tell which check is doing the work. **Design negative vectors with
the minimum number of defects to target a single validation check.
Keep the rest of the encoding valid.**

## 12. Per-File Mutation Testing for Fast Iteration

Full-crate mutation testing takes 30+ minutes. Per-file runs
(`cargo mutants -f src/scalar.rs`) take 2-5 minutes. When
iterating on test design for a specific file's mutations, use
per-file mode for rapid feedback:

```bash
# Fast iteration loop:
# 1. Edit test
# 2. Run per-file mutation test
# 3. Check missed.txt
# 4. Repeat
cargo mutants -j 8 --timeout 120 -f src/scalar.rs
cat mutants.out/missed.txt
```

**Use per-file mode during Phase 5 (vector generation) and
Phase 6 (validation). Only run full-crate tests for the final
before/after comparison.**

## 13. Vectors Have Retroactive and Proactive Value

Mutation testing measures retroactive value: which vectors kill
mutants in existing implementations. But test vectors also have
proactive value: catching bugs in future implementations that
haven't been written yet.

Not-on-curve, wrong-subgroup, and field-boundary vectors killed
zero additional mutants in mature zkcrypto code — the library
already validates these cases. But a new BLS12-381 implementation
that skips a subgroup check or mishandles x ≈ p will fail these
vectors immediately.

**Generate boundary-condition vectors even when they don't improve
mutation kill rates. They're a net for the implementations that
will be written tomorrow, not just the ones that exist today.**

## 14. Go's json.Marshal HTML-Escapes Characters in JSON Output

Go's `json.Marshal` and `json.MarshalIndent` silently HTML-escape
`>`, `<`, and `&` as `\u003e`, `\u003c`, `\u0026` in string values.
This is the default behavior and applies to comment fields, notes,
and any other string in the generated JSON.

Wycheproof's `reformat_json.py` canonicalizes vector files and
unescapes these sequences back to literal characters. The result:
generated vectors fail the `reformat_json.py && git diff --exit-code`
CI check immediately after generation.

**Use `json.NewEncoder` with `SetEscapeHTML(false)` in every Go
vector generator — never `json.Marshal` or `json.MarshalIndent`:**

```go
var buf bytes.Buffer
enc := json.NewEncoder(&buf)
enc.SetEscapeHTML(false)
enc.SetIndent("", "  ")
if err := enc.Encode(data); err != nil { ... }
```

This applies to any string that might contain `>`, `<`, or `&` —
comments like "x >= field prime", notes with HTML, CVE descriptions,
URLs, etc. The same bug will recur silently whenever a new comment
or note uses these characters.
