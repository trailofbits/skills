//! ChaCha20 quarter-round and a 1-round shim. Pure ARX (Add/Rotate/XOR)
//! with no branches and no division -- the textbook CT primitive.
//! Loop bound is fixed (the public number of rounds).

#![crate_type = "lib"]

#[inline(always)]
fn qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline(never)]
pub fn chacha20_block(state: &mut [u32; 16]) {
    let mut work = *state;
    for _ in 0..10 {
        // Column rounds
        qr(&mut work, 0, 4, 8, 12);
        qr(&mut work, 1, 5, 9, 13);
        qr(&mut work, 2, 6, 10, 14);
        qr(&mut work, 3, 7, 11, 15);
        // Diagonal rounds
        qr(&mut work, 0, 5, 10, 15);
        qr(&mut work, 1, 6, 11, 12);
        qr(&mut work, 2, 7, 8, 13);
        qr(&mut work, 3, 4, 9, 14);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(work[i]);
    }
}
