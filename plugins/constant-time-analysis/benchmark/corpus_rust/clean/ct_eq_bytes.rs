//! Constant-time equality on byte slices using XOR-OR accumulation.
//! Mirrors the pattern used by `subtle::ConstantTimeEq` for `[u8]`.
//!
//! Why this is constant-time: every byte is read regardless of value;
//! the accumulator is reduced to a single bit using arithmetic, not a
//! branch. The asm should be a tight loop with no early exit on
//! mismatch. Loop bound is the slice length, which is public.

#![crate_type = "lib"]

#[inline(never)]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        let ai = unsafe { core::ptr::read_volatile(&a[i]) };
        let bi = unsafe { core::ptr::read_volatile(&b[i]) };
        diff |= ai ^ bi;
    }
    let res = ((diff as u32).wrapping_sub(1) >> 31) & 1;
    res as u8
}
