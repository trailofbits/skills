//! DSA / ECDSA nonce reduction with conditional subtraction. The
//! Minerva attack (2020) recovered ECDSA private keys from this
//! exact pattern: a single conditional subtraction whose taken/
//! not-taken decision is made on the most-significant bit of the
//! secret nonce `k`. After ~2^14 signatures, lattice attacks
//! recover the long-term key.

#![crate_type = "lib"]

#[inline(never)]
pub fn nonce_reduce_minerva_vulnerable(k: u64, q: u64) -> u64 {
    // GROUND TRUTH: line 12, kind=branch_on_secret
    if k >= q {
        k - q
    } else {
        k
    }
}

#[inline(never)]
pub fn dsa_compute_s_vulnerable(k_inv: u64, h: u64, x_secret: u64, r: u64, q: u64) -> u64 {
    // The (x * r + h) % q step: % on a secret-derived value.
    let xr = x_secret.wrapping_mul(r);
    let sum = xr.wrapping_add(h);
    // GROUND TRUTH: line 24, kind=div_on_secret
    let reduced = sum % q;
    k_inv.wrapping_mul(reduced) % q
}
