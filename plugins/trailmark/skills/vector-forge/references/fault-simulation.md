# Fault Simulation via Limb-Width Reimplementation

Generate test vectors that catch carry propagation, modular
reduction, and overflow bugs by reimplementing the target
algorithm at non-standard limb widths and deliberately injecting
architectural faults.

## Why Mutation Testing Misses These

Mutation testing frameworks apply local operator swaps (`+` → `-`,
`&` → `|`, `<` → `<=`). They cannot:

- Change the number of limbs in a multi-precision integer
- Alter carry propagation logic across limb boundaries
- Modify reduction strategies (Barrett vs Montgomery vs schoolbook)
- Introduce off-by-one errors in limb iteration bounds

These are exactly the bugs that cause real-world cryptographic
vulnerabilities (e.g., carry bugs in OpenSSL, Go's P-256).

## Methodology

### Step 1: Select Limb Widths

Reimplement the target operation at multiple limb widths to
exercise different carry propagation patterns:

| Limb Width | Why |
|-----------|-----|
| 8-bit | Maximum carries per operation, exposes propagation bugs |
| 16-bit | Intermediate carry frequency, different overflow boundary |
| 25-bit | Non-power-of-2 — exercises radix-2^25 representations (common in constant-time code) |
| 32-bit | Standard width, catches 64-bit-specific assumptions |
| 51-bit | Radix-2^51 (used in curve25519 implementations) |

Choose widths that differ from the production implementation.
If the production code uses 64-bit limbs, test at 8, 25, and
32 bits. If it uses radix-2^25.5 (like ref10), test at 8, 16,
and 32 bits.

### Step 2: Implement a Minimal Reference

You do NOT need a full cryptographic library. Implement only
the specific operation under test:

- **Field arithmetic:** add, subtract, multiply, square, reduce
- **Scalar arithmetic:** multiply, reduce mod group order
- **Point operations:** add, double, scalar multiply

The implementation must:
1. Produce correct results for known test vectors
2. Be simple enough to manually verify (schoolbook algorithms)
3. Use the chosen limb width throughout

### Step 3: Inject Faults

For each reimplementation, introduce ONE fault at a time from
this catalog:

| Fault Category | Specific Fault | What It Catches |
|---------------|----------------|-----------------|
| **Carry propagation** | Drop carry on limb N-1 → N | Missing final carry |
| **Carry propagation** | Off-by-one in carry shift | Carry to wrong bit position |
| **Carry propagation** | Skip carry in multiplication inner loop | Accumulator overflow |
| **Reduction** | Reduce modulo (p+1) instead of p | Wrong modulus |
| **Reduction** | Skip final conditional subtraction | Non-canonical output |
| **Reduction** | Off-by-one in reduction loop bound | Incomplete reduction |
| **Overflow** | Truncate intermediate to limb width before carry | Silent overflow |
| **Overflow** | Use signed instead of unsigned limbs | Sign extension corruption |
| **Boundary** | Return 0 for input = p-1 | Fence-post on modulus boundary |
| **Boundary** | Accept p as valid field element | Off-by-one in validation |

### Step 4: Extract Distinguishing Vectors

For each injected fault:

1. Run the faulted implementation against a broad input set
   (random values + boundary values from the edge-case table)
2. Find inputs where `faulted_output != correct_output`
3. These inputs become test vectors — any correct implementation
   must produce the correct output, and the faulted implementation
   must diverge

**Key insight:** The distinguishing inputs often cluster around
specific value patterns:

| Fault Type | Likely Distinguishing Inputs |
|-----------|----------------------------|
| Carry propagation | Values where limb N-1 is at max (all bits set) |
| Reduction | Values near the modulus: p-1, p-2, 2p-1 |
| Overflow | Products of large values: (p-1) * (p-1) |
| Boundary | Exact modulus, modulus ± 1, zero, one |

### Step 5: Validate Against Production

Run the extracted vectors against the production implementation:

1. If production passes → vector validates production correctness
   for that fault class
2. If production fails → you found a real bug (the production
   implementation has the same fault class)

Both outcomes are valuable. Outcome 2 is a finding.

## Example: Field Multiplication Carry Bug

Target: 256-bit prime field multiplication (4×64-bit limbs in
production).

Reimplementation: 8×32-bit limbs, schoolbook multiplication.

Injected fault: Drop carry from limb 3 → limb 4 in the
multiplication accumulator.

```
Input A: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF (limbs 0-3 maxed)
Input B: 0x00000000_00000000_00000000_00000002 (simple multiplier)

Correct:  A * B mod p = <correct value>
Faulted:  A * B mod p = <wrong value, carry lost at limb boundary>
```

The pair (A, B, correct_result) becomes a test vector. Any
implementation that drops the carry at that boundary will fail.

## Integration with Phase 5

Fault simulation vectors complement mutation-derived vectors:

| Source | Catches |
|--------|---------|
| Mutation testing escapes | Local operator bugs in existing code |
| Fault simulation | Architectural bugs in carry/reduce/overflow logic |

Run fault simulation AFTER mutation testing baseline (Phase 3)
but BEFORE the final validation run (Phase 6). Add fault
simulation vectors to the same test suite as mutation-derived
vectors for the combined before/after comparison.

## Limb-Width Selection Heuristic

For a production implementation with W-bit limbs and N limbs:

1. Always include 8-bit (maximum carry stress)
2. Include at least one non-power-of-2 width (25 or 51 bits)
3. Include a width that is exactly half of production (W/2)
4. If production uses a non-standard radix, include the nearest
   power-of-2 width

This ensures carry boundaries fall at different positions than
production, exposing width-specific assumptions.
