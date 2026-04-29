//! Lucky Thirteen (CVE-2013-0169): TLS CBC-mode padding-oracle attack that
//! recovered HTTP cookies by exploiting timing differences in MAC validation.
//! The bug was that early-exit comparison of the MAC tag returns faster on a
//! mismatched-prefix tag than on a fully-matching tag, leaking which padding
//! byte was correct.
//!
//! Both functions below MUST be flagged: the byte-by-byte loop emits a
//! conditional branch (JNE/JE on x86, B.NE/B.EQ on ARM) whose timing depends
//! on the secret tag, and the early-`return` short-circuit makes it observable
//! by an attacker.

/// Vulnerable MAC verification: returns `true` iff the tags are equal,
/// but bails out on the first mismatching byte.
#[inline(never)]
pub fn verify_mac_vulnerable(expected: &[u8], received: &[u8]) -> bool {
    if expected.len() != received.len() {
        return false;
    }
    // VULNERABLE: branch + early return on secret-derived bytes.
    for i in 0..expected.len() {
        if expected[i] != received[i] {
            return false;
        }
    }
    true
}

/// Same bug, expressed with `==` on `&[u8]`. The stdlib slice eq is itself
/// short-circuiting (it lowers to `bcmp`/`memcmp` which can early-exit on the
/// first differing word). The analyzer flags the conditional branches that
/// the surrounding code introduces.
#[inline(never)]
pub fn verify_token_vulnerable(expected: &[u8; 32], received: &[u8; 32]) -> bool {
    expected == received
}

/// Bleichenbacher / ROBOT-style PKCS#1 v1.5 padding check: the early `return`
/// on each malformed-padding byte is an oracle. The 1998 attack required
/// roughly 2^20 oracle queries to recover an RSA-encrypted session key.
#[inline(never)]
pub fn check_pkcs1_padding_vulnerable(decrypted: &[u8]) -> bool {
    if decrypted.len() < 11 {
        return false;
    }
    if decrypted[0] != 0x00 {
        return false;
    }
    if decrypted[1] != 0x02 {
        return false;
    }
    // Each separator search step is an oracle.
    for &b in &decrypted[2..] {
        if b == 0x00 {
            return true;
        }
    }
    false
}
