# Test Vector Patterns for Cryptographic Primitives

Patterns for designing test vectors that target specific code paths
identified through mutation testing escape analysis.

## Contents

- General principles
- Serialization / deserialization vectors
- Signature scheme vectors
- Hash-to-curve vectors
- Pairing-based cryptography vectors
- Aggregate / threshold scheme vectors
- Key encapsulation vectors
- Symmetric cipher vectors
- Mapping escaped mutants to vector patterns

---

## General Principles

### Every Vector Needs a Purpose

Each test vector should target a specific code path or validation
check. Document the purpose in the vector's `comment` field:

```json
{
  "tcId": 5,
  "comment": "signature with flipped sign bit in G2 y-coordinate",
  "result": "invalid",
  "flags": ["ModifiedSignature"]
}
```

### Cross-Implementation Verification is Mandatory

A test vector is only trustworthy if two independent implementations
agree on its result. If they disagree, one has a bug — and that
disagreement is itself a valuable finding.

### Negative Vectors are More Valuable Than Positive Ones

Valid-case vectors verify basic correctness. Invalid-case vectors
exercise error handling, validation, and rejection logic — the code
paths where security bugs hide.

### Edge Cases Over Random Cases

Random test vectors exercise the "happy path." Edge cases exercise
boundary conditions where off-by-one errors, overflow, and
validation gaps lurk.

---

## Serialization / Deserialization Vectors

Target: `SetBytes`, `FromCompressed`, `Decode`, `Unmarshal`,
`from_bytes`, `deserialize` and similar functions.

### Point Encoding Vectors (Elliptic Curves)

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| Valid compressed point | Baseline correctness | valid |
| Valid uncompressed point | Baseline for uncompressed path | valid |
| Identity / point at infinity | Special case handling | valid or invalid (spec-dependent) |
| Wrong length (truncated) | Length validation | invalid |
| Wrong length (extra bytes) | Length validation | invalid |
| All-zero bytes | Zero-check handling | invalid |
| Field element >= modulus | Field validation | invalid |
| Point not on curve | Curve check | invalid |
| Point on curve but wrong subgroup | Subgroup check | invalid |
| Flipped compression flag bit | Flag parsing | invalid |
| Flipped sign bit | Sign selection | invalid or different point |
| Maximum valid field element | Boundary condition | valid |
| Modulus - 1 as field element | Boundary condition | valid |
| Mixed compressed/uncompressed flags | Flag consistency | invalid |

### Roundtrip Assertions

For every valid deserialization vector, add a roundtrip check:
`serialize(deserialize(bytes)) == bytes`. This catches field
arithmetic corruption (carry propagation, modular reduction,
square root, negation bugs) that produces a valid-looking but
incorrect point — the wrong y-coordinate changes the sort bit
in the re-compressed encoding.

This technique killed 15 previously-missed `Fp` mutations in
the BLS12-381 campaign without requiring knowledge of the
internal field representation.

### Single-Fault Negative Vectors

Each negative vector should isolate ONE validation check by
having exactly one defect. For flag parsing mutations:

| Defect | Construction | Validates |
|--------|-------------|-----------|
| Compression flag cleared | `bytes[0] &= 0x7f` on valid point | Flag bit 7 check |
| Infinity flag set | `bytes[0] \|= 0x40` on non-identity | Flag bit 6 check |
| Sort flag on identity | `bytes = [0xe0, 0, ...]` | Identity + flag consistency |
| Compression cleared on identity | `bytes = [0x40, 0, ...]` | Identity encoding check |
| Both infinity + sort | `bytes[0] \|= 0x60` on valid point | Multi-flag validation |
| Wrong length | 192 bytes with compression flag | Length vs flag consistency |

Keep the underlying field element valid so the ONLY reason for
rejection is the flag. This is what kills `&` → `|` mutations
in `from_compressed_unchecked`.

### Scalar Encoding Vectors

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| Zero scalar | Zero handling | valid (context-dependent) |
| One scalar | Identity element | valid |
| Group order - 1 | Maximum valid | valid |
| Group order | Reduction check | invalid or reduced to zero |
| Group order + 1 | Overflow handling | invalid or reduced to one |
| All-ones bytes | Large value handling | invalid (usually > order) |
| Non-canonical encoding | Reduction behavior | depends on spec |

---

## Signature Scheme Vectors

Target: `Verify`, `Sign`, `verify`, `core_verify` and similar.

### Single Signature Vectors

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| Valid signature on empty message | Empty input handling | valid |
| Valid signature on single byte | Minimal input | valid |
| Valid signature on large message | No length limits | valid |
| Wrong message (1 bit flip) | Verification correctness | invalid |
| Wrong public key | Key binding | invalid |
| Truncated signature | Length check | invalid |
| Signature with extra bytes | Strict parsing | invalid |
| Identity point as signature | Identity rejection | invalid |
| Identity point as public key | Identity rejection | invalid |
| Negated signature | Sign check | invalid |
| Signature from wrong scheme/DST | Cross-scheme isolation | invalid |
| All-zero signature bytes | Degenerate input | invalid |
| Signature with field overflow | Field validation | invalid |

### Multi-Signature / Aggregate Vectors

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| 1 signer, valid | Minimal aggregate | valid |
| N signers, all valid | Standard case | valid |
| N signers, one wrong message | Detects per-message binding | invalid |
| Mismatched pubkey/message count | Input validation | invalid |
| Empty signer list | Empty input handling | invalid |
| Duplicate messages (rogue key attack) | See spec requirements | invalid |
| Identity key in aggregate | Identity rejection | invalid |
| Identity signature in aggregate | Identity rejection | invalid |

---

## Hash-to-Curve Vectors

Target: `HashToG1`, `HashToG2`, `hash_to_curve`, `encode_to_curve`.

### Known Answer Tests (KATs)

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| Empty message | Empty input handling | known point |
| Single byte 0x00 | Minimal non-empty | known point |
| ASCII string "abc" | Standard test | known point |
| Long message (128+ bytes) | No length restrictions | known point |
| Very long message (256+ bytes) | Large input handling | known point |
| RFC test vectors | Spec compliance | known point |

Hash-to-curve vectors must use a specific DST (domain separation
tag) and the expected output must be computed by a reference
implementation.

---

## Pairing-Based Cryptography Vectors

Target: `PairingCheck`, `MillerLoop`, `FinalExponentiation`,
`multi_miller_loop`, `pairing`.

### Pairing Check Vectors

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| e(P, Q) == e(P, Q) | Reflexivity | pass |
| e(aP, Q) == e(P, aQ) | Bilinearity | pass |
| e(P, O) == 1 | Identity handling (O = point at infinity) | pass |
| e(O, Q) == 1 | Identity handling | pass |
| e(P, Q) with P not in G1 | Subgroup check | fail or undefined |
| e(P, Q) with Q not in G2 | Subgroup check | fail or undefined |
| Multi-pairing with n=1 | Minimal multi-pairing | matches single pairing |
| Multi-pairing with n=0 | Empty input | implementation-defined |

---

## Key Encapsulation Vectors (KEM)

Target: `Encapsulate`, `Decapsulate`, `encaps`, `decaps`.

| Vector Type | Purpose | Expected Result |
|-------------|---------|-----------------|
| Valid encaps/decaps roundtrip | Correctness | shared secrets match |
| Modified ciphertext (1 bit flip) | Ciphertext integrity | decaps fails or different secret |
| Wrong secret key | Key binding | decaps fails or different secret |
| Truncated ciphertext | Length validation | error |
| All-zero ciphertext | Degenerate input | error |
| Known-answer test (deterministic encaps) | Spec compliance | known ciphertext + secret |

---

## Mapping Escaped Mutants to Vector Patterns

When escape analysis (Phase 4) identifies survived mutants, use
this mapping to select appropriate vector patterns:

| Mutant Location | Mutant Type | Vector Pattern |
|-----------------|-------------|----------------|
| Length check (`len != N`) | CONDITIONALS_BOUNDARY | Truncated / extended inputs |
| Field validation (`>= modulus`) | CONDITIONALS_NEGATION | Field overflow values |
| Subgroup check | CONDITIONALS_NEGATION | Wrong-subgroup points |
| Identity check (`IsInfinity`) | CONDITIONALS_NEGATION | Identity point inputs |
| Sign bit handling | ARITHMETIC_BASE | Negated / flipped-sign inputs |
| Error return path | CONDITIONALS_NEGATION | Input triggering that error |
| Serialization flag parsing | ARITHMETIC_BASE | All flag combinations |
| Loop bound (`i < n`) | INCREMENT_DECREMENT | Boundary-length inputs |
| Arithmetic operation | INVERT_NEGATIVES | KATs verifying exact output |

### Example: Mapping gnark-crypto BLS12-381 Escapes

```
marshal.go:117-352 (streaming encoder, NOT COVERED)
→ Not reachable via SetBytes/Bytes API
→ Need vectors exercising io.Writer-based Encode/Decode
→ Pattern: Serialization vectors via streaming API

pairing.go:352-394 (Miller loop internals, NOT COVERED)
→ Reachable via PairingCheck but specific arithmetic lines
  don't have distinguishing inputs
→ Pattern: Pairing bilinearity KATs with edge-case points

g1.go:184, g2.go:191 (endomorphism, NOT COVERED)
→ Only used in multi-scalar multiplication optimization
→ Pattern: Large-scalar multiplication with known answers
```
