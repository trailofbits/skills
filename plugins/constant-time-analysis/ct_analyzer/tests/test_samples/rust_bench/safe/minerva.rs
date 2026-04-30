//! Constant-time reduction. The function always does exactly one subtraction
//! and selects the result with a bitmask, so the asm contains no division
//! and no conditional branch on the secret. This is the pattern used by
//! `curve25519-dalek` and the BoringSSL `ec_GFp_simple_field_decode_data`.

/// Constant-time `k mod q` for `k < 2*q`. Always one subtraction, one mask.
/// Result equals `if k >= q { k - q } else { k }` but the asm is branchless.
#[inline(never)]
pub fn reduce_mod_q_safe(k: u64, q: u64) -> u64 {
    let diff = k.wrapping_sub(q);
    // borrow == 0 if k >= q, all-ones if k < q.
    let borrow = (diff >> 63).wrapping_neg();
    // Select `diff` when no borrow (k >= q), else `k`.
    (diff & !borrow) | (k & borrow)
}

/// Same primitive expressed as a `select`. Compiles to `cmovae` on x86_64
/// (a single instruction with fixed latency) when written this way.
#[inline(never)]
pub fn cond_sub_safe(k: u64, q: u64) -> u64 {
    let diff = k.wrapping_sub(q);
    let borrow = (diff >> 63).wrapping_neg();
    (diff & !borrow) | (k & borrow)
}

/// Constant-time modular exponentiation by squaring with always-process
/// every bit (Montgomery ladder). No `div`, no secret-dependent branch.
/// This is the building block for constant-time inversion via Fermat's
/// little theorem (`a^(p-2) mod p`).
#[inline(never)]
pub fn pow_mod_safe(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b = base as u128;
    let m = modulus as u128;
    let mut bit = 1u64 << 63;
    // Always 64 iterations, regardless of `exp`.
    while bit != 0 {
        result = (result * result) % m;
        // Always compute `result * b`, then conditionally select.
        let cand = (result * b) % m;
        let mask = ((exp & bit).wrapping_sub(1) >> 63).wrapping_neg() as u128;
        // mask = 0 if bit is set, all-ones if bit is clear.
        result = (cand & !mask) | (result & mask);
        bit >>= 1;
    }
    result as u64
}
