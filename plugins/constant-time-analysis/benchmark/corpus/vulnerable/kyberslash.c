/*
 * KyberSlash (2023) pattern - synthetic.
 *
 * Original ML-KEM `decompose` reduces a polynomial coefficient by GAMMA2.
 * The compiler emits an `idiv` because GAMMA2 is not a power of two.
 * The dividend is derived from the secret key, so the variable-time
 * division leaks key bits via execution time.
 *
 * Real-world impact: KyberSlash 1 & 2 (Bernstein, Lange et al., 2023)
 * recovered ML-KEM private keys from server-side timing.
 *
 * Ground truth: line 27 has a real timing leak (idiv on secret).
 *               line 32 is also a real leak (a different variant).
 */

#include <stdint.h>

#define GAMMA2 ((1 << 15) - 1)        /* not a power of two on purpose */

/* secret_coef is derived from the private key */
int32_t kyberslash_decompose(int32_t secret_coef) {
    int32_t r1, r0;
    /* VULNERABLE: divisor GAMMA2 is constant but not a shift-friendly value,
     * compiler emits IDIV.  Dividend is secret. */
    r1 = secret_coef / GAMMA2;
    r0 = secret_coef - r1 * GAMMA2;
    return r1 ^ r0;
}

int32_t kyberslash_reduce(int32_t secret) {
    /* VULNERABLE: variable-divisor reduction. */
    return secret % 3329;             /* Kyber Q = 3329, also non-power-of-2 */
}

/* Helper that is NOT vulnerable: dividing a public length is safe. */
int public_block_count(int data_len) {
    return data_len / 16;             /* false positive if naively flagged */
}
