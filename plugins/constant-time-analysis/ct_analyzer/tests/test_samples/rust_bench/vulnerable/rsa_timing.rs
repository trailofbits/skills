//! RSA timing attack family. Kocher 1996 showed that a square-and-multiply
//! implementation that skips multiplications when the exponent bit is zero
//! leaks the exponent through total runtime. With `d` being the RSA private
//! exponent, every leaked bit halves the search space for the rest.
//!
//! Both functions below MUST be flagged: `square_and_multiply_vulnerable` for
//! the secret-dependent branch on `bit_set`, and `divisor_attempt_vulnerable`
//! for the IDIV that the trial-division-style fallback emits.

/// Square-and-multiply with conditional multiply.
#[inline(never)]
pub fn square_and_multiply_vulnerable(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result: u128 = 1;
    let b = base as u128;
    let m = modulus as u128;
    for i in 0..64 {
        result = (result * result) % m;
        // VULNERABLE: branch on a bit of the secret exponent. Skipping the
        // multiplication when the bit is zero is the textbook timing leak.
        if (exp >> (63 - i)) & 1 == 1 {
            result = (result * b) % m;
        }
    }
    result as u64
}

/// Trial-division GCD that an unsafe RSA blinding routine might use to test
/// whether a candidate is coprime with `n`. The IDIV makes the per-step
/// timing depend on the operand magnitudes.
#[inline(never)]
pub fn gcd_vulnerable(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        // VULNERABLE: u64 IDIV / DIV on secret operand.
        let r = a % b;
        a = b;
        b = r;
    }
    a
}
