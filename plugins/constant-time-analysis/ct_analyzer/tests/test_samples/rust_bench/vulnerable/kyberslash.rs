//! KyberSlash (CVE-2024-37880, CVE-2024-39998): division on secret coefficients
//! during ML-KEM (Kyber) decryption leaks the coefficient through DIV timing.
//! The original attack recovered the secret key from a few thousand decryption
//! timing measurements on Cortex-M cores.
//!
//! IMPORTANT: this benchmark exposes two flavours. The first uses a
//! parameterized modulus (`q: u32`) and is universally detectable as `IDIV`
//! on every architecture with hardware divide. The second uses the
//! compile-time constant `Q = 3329` exactly as upstream Kyber did; the
//! compiler folds the divisor into a magic-multiply on x86_64 (so no `DIV`
//! appears in the asm), but the same pattern still emits a software-divide
//! call on Cortex-M3 (no hardware divider) and a variable-latency multiply
//! on Cortex-M4 -- which is how the real exploit worked.
//!
//! The analyzer correctly flags the first form on x86_64 / arm64 / arm.
//! For the constant-Q form, run with `--arch arm` to expose the soft-divide
//! call (rustc emits `__udivsi3` / `__umodsi3`, which the analyzer sees as
//! a `BL` to a runtime helper -- still a useful flag).

const Q_CONST: i32 = 3329;

/// Parameterized-Q form: matches a generic post-quantum lattice implementation
/// where the modulus is part of the parameter set. The compiler MUST emit a
/// hardware divide because `q` is unknown at compile time.
///
/// Universally detectable: x86_64 emits `idivl`, arm64 emits `sdiv`, arm
/// emits `sdiv` (ARMv7-M+) or a soft-divide call (Cortex-M3).
#[inline(never)]
pub fn compress_paramq_vulnerable(coeff: i32, q: i32, d: u32) -> i32 {
    // VULNERABLE: hardware integer division on a secret-derived value.
    let scaled = coeff << d;
    let quotient = (scaled + (q / 2)) / q;
    quotient & ((1 << d) - 1)
}

/// Decryption hot loop with parameterized-Q. KyberSlash measured the
/// cumulative timing of the per-coefficient division across the whole
/// polynomial.
#[inline(never)]
pub fn decompress_loop_paramq_vulnerable(coeffs: &mut [i32; 256], q: i32, d: u32) {
    let mask = (1i32 << d) - 1;
    for c in coeffs.iter_mut() {
        let v = (*c & mask) * q + (1 << (d - 1));
        *c = v >> d;
        // VULNERABLE: secret-dependent IDIV + IMOD.
        *c %= q;
    }
}

/// Constant-Q form: faithful reproduction of the upstream PQClean
/// `poly_compress` pre-fix code. Detection on x86_64 requires a cross-arch
/// run because the compiler's constant-divisor magic-multiply hides the DIV.
/// See module-level docs.
#[inline(never)]
pub fn compress_constq_vulnerable(coeff: i16, d: u32) -> i16 {
    let scaled = (coeff as i32) << d;
    let quotient = (scaled + (Q_CONST / 2)) / Q_CONST;
    (quotient & ((1 << d) - 1)) as i16
}
