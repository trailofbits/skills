//! Constant-time conditional select / swap, the building blocks of
//! every CT crypto primitive. The compiled asm should be a bitmask
//! blend, no `cmov` on the secret, no branch.

#![crate_type = "lib"]

#[inline(never)]
pub fn ct_select_u32(cond_bit: u8, a: u32, b: u32) -> u32 {
    let mask = 0u32.wrapping_sub(cond_bit as u32 & 1);
    (a & mask) | (b & !mask)
}

#[inline(never)]
pub fn ct_swap_u64(cond_bit: u8, a: &mut u64, b: &mut u64) {
    let mask = 0u64.wrapping_sub(cond_bit as u64 & 1);
    let t = (*a ^ *b) & mask;
    *a ^= t;
    *b ^= t;
}

#[inline(never)]
pub fn ct_negate_if(cond_bit: u8, x: i64) -> i64 {
    let mask = 0i64.wrapping_sub(cond_bit as i64 & 1);
    (x ^ mask).wrapping_sub(mask)
}
