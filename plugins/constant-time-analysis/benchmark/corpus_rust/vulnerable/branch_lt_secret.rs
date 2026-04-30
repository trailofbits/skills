//! "Compare-then-branch" on secret operands: returning 1 vs 0 with a
//! conditional. Should have been `((a as u64).wrapping_sub(b as u64) >> 63) & 1`
//! (a CT subtraction) but the developer wrote the obvious thing.

#![crate_type = "lib"]

#[inline(never)]
pub fn ct_lt_naive(a: u64, b: u64) -> u8 {
    // GROUND TRUTH: line 10, kind=branch_on_secret
    if a < b { 1 } else { 0 }
}

#[inline(never)]
pub fn modular_reduce_naive(k: u64, q: u64) -> u64 {
    // GROUND TRUTH: line 16, kind=branch_on_secret
    // Variable iteration count: leaks `k / q` via total runtime.
    let mut k = k;
    while k >= q {
        k -= q;
    }
    k
}
