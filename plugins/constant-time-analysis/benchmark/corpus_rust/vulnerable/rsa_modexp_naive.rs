//! Naive RSA modular exponentiation: square-and-multiply with a
//! conditional multiply. Each bit of the secret exponent that is set
//! costs an extra multiplication, leaking the exponent through total
//! runtime. This is the textbook Kocher 1996 timing attack.

#![crate_type = "lib"]

#[inline(never)]
pub fn rsa_modexp_naive(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result: u128 = 1;
    let b = base as u128;
    let m = modulus as u128;
    for i in 0..64 {
        result = (result * result) % m;
        // GROUND TRUTH: line 16, kind=branch_on_secret
        if (exp >> (63 - i)) & 1 == 1 {
            // GROUND TRUTH: line 18, kind=div_on_secret
            // (the % m on the conditional multiplication path)
            result = (result * b) % m;
        }
    }
    result as u64
}

#[inline(never)]
pub fn rsa_modinv_euclid_vulnerable(mut a: u64, mut m: u64) -> u64 {
    // Extended Euclidean algorithm; iteration count and DIV operands
    // both depend on `a` (a secret in the RSA d/p/q recovery context).
    let m0 = m as i64;
    let (mut x0, mut x1) = (0i64, 1i64);
    while a > 1 {
        // GROUND TRUTH: line 32, kind=div_on_secret
        let q = a / m;
        let t = m;
        m = a % m;
        a = t;
        let t2 = x0;
        x0 = x1 - (q as i64) * x0;
        x1 = t2;
    }
    if x1 < 0 {
        x1 += m0;
    }
    x1 as u64
}
