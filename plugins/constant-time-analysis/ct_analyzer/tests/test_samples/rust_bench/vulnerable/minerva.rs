//! Minerva (CVE-2019-15809 family): an ECDSA nonce reduction that uses an
//! input-dependent number of conditional subtractions leaks the most
//! significant bits of the per-signature nonce `k`. With ~2^14 signatures the
//! attacker recovers the long-term private key via a lattice attack.
//!
//! The same pattern recurs in PKCS#11 modules, libgcrypt, MatrixSSL, and at
//! least three smartcards. We reproduce two flavours: the loop-based reducer
//! (variable iterations) and the leaky modular inverse (variable-time `gcd`).
//!
//! Both functions MUST be flagged for division and/or conditional branches.

/// Reduces `k` modulo `q` by repeated subtraction. The number of loop
/// iterations is `k / q`, which is secret. Each iteration emits a
/// conditional branch in the compiled asm.
#[inline(never)]
pub fn reduce_mod_q_vulnerable(k: u64, q: u64) -> u64 {
    let mut k = k;
    while k >= q {
        // VULNERABLE: branch on a secret value, executed an input-dependent
        // number of times.
        k -= q;
    }
    k
}

/// "Conditional subtraction" idiom written as a single `if`. This compiles
/// to a JCC + a branch target -- a binary timing oracle that Minerva
/// successfully exploited at the bit level on real ECDSA signers.
#[inline(never)]
pub fn cond_sub_vulnerable(k: u64, q: u64) -> u64 {
    if k >= q {
        k - q
    } else {
        k
    }
}

/// Variable-time modular inverse (extended Euclidean). The number of inner
/// iterations depends on the bit pattern of the inputs; this leaks the
/// scalar through cache and total-runtime side channels.
#[inline(never)]
pub fn modinv_vulnerable(mut a: u64, mut m: u64) -> u64 {
    if m == 0 {
        return 0;
    }
    let m0 = m as i64;
    let (mut x0, mut x1) = (0i64, 1i64);
    while a > 1 {
        // VULNERABLE: u64 division on a secret-derived value.
        let q = a / m;
        let t = m;
        m = a % m;
        a = t;
        let t = x0;
        x0 = x1 - (q as i64) * x0;
        x1 = t;
    }
    if x1 < 0 {
        x1 += m0;
    }
    x1 as u64
}
