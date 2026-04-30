//! HKDF-Expand-style update loop. Iterations are bounded by the *output
//! length* (caller-provided, public), and each step calls into HMAC
//! which itself is constant-time (XOR / SHA core / no division).
//! Branches here are on public output-length bookkeeping.

#![crate_type = "lib"]

#[inline(always)]
fn hmac_sha256_stub(_key: &[u8], _data: &[u8], out: &mut [u8; 32]) {
    // Stub: a real HMAC-SHA256 fills `out`. Kept as a black box so
    // the analyzer doesn't see into it; the loop control around it
    // is what we want to evaluate.
    for b in out.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0xAA) };
    }
}

#[inline(never)]
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let n = (okm.len() + 31) / 32;
    let mut t_prev = [0u8; 32];
    let mut counter: u8 = 1;
    let mut written: usize = 0;
    let mut buf = [0u8; 32];
    for i in 0..n {
        // Build T(i) input: T(i-1) || info || counter.
        let _ = i;
        hmac_sha256_stub(prk, info, &mut buf);
        let take = core::cmp::min(32, okm.len() - written);
        okm[written..written + take].copy_from_slice(&buf[..take]);
        written += take;
        t_prev = buf;
        counter = counter.wrapping_add(1);
    }
    let _ = t_prev;
    let _ = counter;
}
