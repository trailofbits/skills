//! KyberSlash analogue (CVE-2024-37880 family): hardware integer
//! division on a secret-derived coefficient. The runtime modulus `q`
//! defeats const-divisor magic-multiply, forcing rustc to emit IDIV.

#![crate_type = "lib"]

#[inline(never)]
pub fn compress_paramq_vulnerable(secret_coef: i32, q: i32, d: u32) -> i32 {
    let scaled = secret_coef << d;
    // GROUND TRUTH: line 11, kind=div_on_secret
    let quotient = (scaled + (q / 2)) / q;
    quotient & ((1 << d) - 1)
}

#[inline(never)]
pub fn decompress_paramq_vulnerable(coeffs: &mut [i32; 256], q: i32) {
    for c in coeffs.iter_mut() {
        // GROUND TRUTH: line 19, kind=div_on_secret
        *c %= q;
    }
}
