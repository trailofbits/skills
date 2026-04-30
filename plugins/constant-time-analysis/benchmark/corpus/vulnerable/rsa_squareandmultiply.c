/*
 * RSA timing pattern - synthetic.
 *
 * Naive square-and-multiply modular exponentiation branches on each bit of
 * the private exponent.  The classic Kocher 1996 timing attack recovers the
 * key by measuring per-iteration latency.
 *
 * Ground truth: lines 22-25 contain secret-dependent branch (bit of d).
 *               line 30 has variable-time modular reduction (idiv).
 */

#include <stdint.h>

uint64_t naive_modexp(uint64_t base, uint64_t exp_secret, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;                       /* idiv on public arg base, false positive */
    /* loop counter is public (bit length), not secret */
    for (int i = 0; i < 64; i++) {
        /* VULNERABLE: branch on each bit of the secret exponent. */
        if (exp_secret & 1) {
            result = (result * base) % mod;     /* VULNERABLE idiv */
        }
        exp_secret >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

/* SAFE alternative: ladder always runs both branches (Montgomery ladder). */
uint64_t montgomery_ladder(uint64_t base, uint64_t exp_secret, uint64_t mod) {
    uint64_t r0 = 1, r1 = base % mod;
    for (int i = 63; i >= 0; i--) {
        uint64_t bit = (exp_secret >> i) & 1;
        /* still uses %, which is variable-time, but no secret BRANCH */
        uint64_t mask = -bit;
        uint64_t temp0 = (r0 & ~mask) | (r1 & mask);
        uint64_t temp1 = (r0 & mask) | (r1 & ~mask);
        (void)temp0; (void)temp1;
        r0 = (r0 * r0) % mod;
        r1 = (r0 * r1) % mod;
    }
    return r0;
}
