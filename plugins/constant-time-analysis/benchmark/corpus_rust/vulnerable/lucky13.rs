//! Lucky 13 analogue (CVE-2013-0169): MAC-validation loop whose
//! iteration count is secret-derived. The iteration bound is
//! `padding_len + 1`, which depends on the decrypted padding byte
//! (a secret). Every additional padding byte adds a measurable
//! number of HMAC compression rounds, leaking the padding length.

#![crate_type = "lib"]

#[inline(never)]
pub fn lucky13_mac_check(decrypted: &[u8], expected_mac: &[u8]) -> bool {
    let n = decrypted.len();
    if n < 16 {
        return false;
    }
    // Padding length is the last byte of the decrypted block.
    let pad_len = decrypted[n - 1] as usize;
    if pad_len >= n {
        return false;
    }
    let msg_len = n - pad_len - 1;

    // GROUND TRUTH: line 23, kind=secret_loop_bound
    // The loop bound is secret-derived (msg_len depends on pad_len).
    let mut acc = 0u8;
    for i in 0..msg_len {
        acc ^= decrypted[i];
    }

    // GROUND TRUTH: line 31, kind=memcmp_on_secret
    // Naive == on byte slices: lowers to a short-circuiting compare.
    expected_mac == &decrypted[msg_len..msg_len + expected_mac.len()]
        && acc != 0xFF
}
