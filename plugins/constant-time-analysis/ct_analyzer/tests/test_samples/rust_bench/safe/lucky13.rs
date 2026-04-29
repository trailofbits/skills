//! Constant-time MAC / padding verification.
//!
//! The pattern matches `subtle::ConstantTimeEq` and `ring::constant_time::
//! verify_slices_are_equal`. Every byte is XORed and OR-accumulated; the
//! result is reduced to `0` (equal) or non-zero (unequal) using bit twiddling
//! that emits no branch. This file is a *negative control*: the analyzer
//! should report no errors and no warnings even with `--warnings` enabled.

/// Constant-time tag comparison. Must process every byte regardless of
/// content, then collapse the difference to a single bit. The `volatile_read`
/// shim prevents LLVM from realising the accumulator is dead and replacing
/// the loop with a `bcmp`.
#[inline(never)]
pub fn verify_mac_safe(expected: &[u8], received: &[u8]) -> bool {
    if expected.len() != received.len() {
        // Length is public (transmitted in the cleartext header), so a length
        // check is fine. The byte-content path below is constant-time.
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..expected.len() {
        // Fence the read to keep the compiler from short-circuiting.
        let a = unsafe { core::ptr::read_volatile(&expected[i]) };
        let b = unsafe { core::ptr::read_volatile(&received[i]) };
        diff |= a ^ b;
    }
    // Reduce `diff` to 1 iff every byte matched, with no branch.
    let res = ((diff as u32).wrapping_sub(1) >> 31) & 1;
    res == 1
}

/// PKCS#1 v1.5 padding check rewritten so every byte is examined and the
/// "first 0x00 separator index" is computed without a data-dependent branch.
/// We accumulate "have we seen a zero yet?" as a bitmask.
#[inline(never)]
pub fn check_pkcs1_padding_safe(decrypted: &[u8]) -> u32 {
    if decrypted.len() < 11 {
        return 0;
    }
    let header_ok = ct_eq_u8(decrypted[0], 0x00) & ct_eq_u8(decrypted[1], 0x02);
    let mut seen_zero: u32 = 0;
    for &b in &decrypted[2..] {
        seen_zero |= ct_eq_u8(b, 0x00);
    }
    header_ok & seen_zero
}

/// Produces `1` if `a == b`, else `0`, using only arithmetic.
#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u32 {
    let x = (a ^ b) as u32;
    // `x.wrapping_sub(1) >> 31` is 1 iff x == 0.
    (x.wrapping_sub(1) >> 31) & 1
}
