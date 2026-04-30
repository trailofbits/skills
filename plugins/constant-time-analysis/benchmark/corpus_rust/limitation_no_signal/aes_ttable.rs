//! AES with T-table lookups. The classical CACHE-timing attack target
//! (Bernstein 2005, Osvik/Shamir/Tromer 2006) -- but the *instruction*
//! stream is data-independent: just memory loads at secret-derived
//! indices. An instruction-level analyzer cannot see this leak; it
//! requires either microarchitectural simulation or dynamic profiling
//! (e.g. ctgrind, dudect, LLVM-CT).
//!
//! GROUND TRUTH: zero violations expected from THIS analyzer. This
//! file documents a known blind spot, not a detection target.

#![crate_type = "lib"]

const SBOX: [u8; 256] = [0u8; 256];

#[inline(never)]
pub fn aes_subbytes_ttable(state: &mut [u8; 16]) {
    for i in 0..16 {
        // Memory load at a secret-derived index. Instruction-level
        // analysis sees a normal MOV; cache timing leaks the index.
        state[i] = SBOX[state[i] as usize];
    }
}
