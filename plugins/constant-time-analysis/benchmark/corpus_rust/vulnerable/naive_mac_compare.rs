//! Naive memcmp-style MAC comparisons in Rust. The Rust ecosystem's
//! reputation calls `==` on byte slices "the silent footgun", but the
//! reality is more nuanced and the analyzer's behaviour reflects that:
//!
//! 1. `[u8; N] == [u8; N]` (fixed-size array): rustc lowers to
//!    `pcmpeqb` (SIMD compare-bytes) at -O2/-O3 -- fully data-
//!    independent at the per-byte level. NOT a planted bug.
//! 2. `&[u8] == &[u8]` (slice): rustc emits a length check (`jne` on
//!    public length) then calls `bcmp` (variable-time on glibc but the
//!    JE/JNE in the user's asm is on length only, not on contents).
//!    The data-dependent branch lives inside libc, attributed to the
//!    libc binary -- not visible to this analyzer's source-attribution.
//! 3. Manual loop with early-exit: real, visible JE/JNE per byte. THIS
//!    is the planted bug the analyzer must catch.
//!
//! So the curated GT for this file has only ONE planted bug, not three.
//! The other two functions stay so we can show that the analyzer
//! correctly does NOT flag them as variable-time at the asm level.

#![crate_type = "lib"]

#[inline(never)]
pub fn verify_mac_array_pcmpeqb(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    // NOT vulnerable in compiled asm: lowers to pcmpeqb (CT SIMD compare).
    // The result IS variable-time at the call site, but that's a separate
    // issue from "the comparison itself".
    computed == expected
}

#[inline(never)]
pub fn verify_mac_slice_length_branch(computed: &[u8], expected: &[u8]) -> bool {
    // The JE/JNE in this function's asm is on SLICE LENGTH, which is
    // public. The data compare is `bcmp` (libc), which lives outside
    // the user's asm and is not seen by an instruction-level analyzer.
    computed == expected
}

#[inline(never)]
pub fn verify_signature_early_exit(sig_a: &[u8], sig_b: &[u8]) -> bool {
    if sig_a.len() != sig_b.len() {
        return false;
    }
    // GROUND TRUTH: variable-time per-byte loop with early exit.
    for i in 0..sig_a.len() {
        if sig_a[i] != sig_b[i] {
            return false;
        }
    }
    true
}
