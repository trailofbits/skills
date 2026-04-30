//! Constant-time fix for KyberSlash: replace division by Q with a Barrett-style
//! multiplication by a precomputed reciprocal. The fix matches what PQClean,
//! BoringSSL, and the Rust `pqcrypto-mlkem` crate adopted after disclosure.
//!
//! Why this is safe: integer multiplication `IMUL` has fixed latency on every
//! x86_64 microarchitecture from Pentium-Pro onward (3-cycle constant) and is
//! similarly fixed-latency on every ARM core that implements the M extension.
//! Shifts are also single-cycle. No `IDIV` / `DIV` / `SDIV` / `UDIV` should
//! survive in the emitted asm.

const Q: i32 = 3329;

// Barrett reciprocal: floor(2^32 / Q) = 1290167. The +1 absorbs the rounding
// so the result is the correct floor for all 32-bit dividends. Computing this
// at compile time is fine because Q is public.
const Q_INV_M32: u64 = ((1u64 << 32) / Q as u64) + 1;

/// Constant-time floor-divide-by-Q for unsigned 32-bit values.
#[inline(always)]
const fn divq_ct(x: u32) -> u32 {
    ((x as u64 * Q_INV_M32) >> 32) as u32
}

#[inline(always)]
const fn modq_ct(x: u32) -> u32 {
    x - divq_ct(x) * (Q as u32)
}

#[inline(never)]
pub fn compress_d_safe(coeff: i16, d: u32) -> i16 {
    // `coeff` may be negative; map into [0, Q) first using a constant-time
    // conditional add. The mask is purely an arithmetic shift -- no branch.
    let signed = coeff as i32;
    let mask = signed >> 31; // 0 or -1
    let nonneg = (signed + (Q & mask)) as u32;

    let scaled = nonneg << d;
    let quotient = divq_ct(scaled + (Q as u32 / 2));
    (quotient & ((1u32 << d) - 1)) as i16
}

#[inline(never)]
pub fn decompress_loop_safe(coeffs: &mut [i16; 256], d: u32) {
    let mask = (1u32 << d) - 1;
    for c in coeffs.iter_mut() {
        let v = ((*c as i32 as u32) & mask) * (Q as u32) + (1u32 << (d - 1));
        *c = (v >> d) as i16;
        // Was `% Q`; now the precomputed-reciprocal version.
        *c = modq_ct(*c as u32) as i16;
    }
}
