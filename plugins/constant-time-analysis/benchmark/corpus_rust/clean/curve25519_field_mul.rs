//! 5-limb radix-2^51 field multiplication for Curve25519, mirroring the
//! curve25519-dalek `FieldElement::mul` shape. Wrapping mul + add only,
//! no division (the modular reduction uses shifts and adds because the
//! prime 2^255 - 19 is a Mersenne-like form).

#![crate_type = "lib"]

#[inline(never)]
pub fn fe_mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;
    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    // Carry propagation (each shift right is by a public bit count).
    const MASK: u128 = (1u128 << 51) - 1;
    let c = r0 >> 51;
    let r0 = r0 & MASK;
    let r1 = r1 + c;
    let c = r1 >> 51;
    let r1 = r1 & MASK;
    let r2 = r2 + c;
    let c = r2 >> 51;
    let r2 = r2 & MASK;
    let r3 = r3 + c;
    let c = r3 >> 51;
    let r3 = r3 & MASK;
    let r4 = r4 + c;
    let c = r4 >> 51;
    let r4 = r4 & MASK;
    let r0 = r0 + c * 19;

    [r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64]
}
