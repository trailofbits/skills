/*
 * AES T-table style cache-timing leak (synthetic).
 *
 * The original variable-time AES (T-table) lookup uses secret bytes as
 * indices into a 256-entry precomputed table.  Cache misses leak which
 * indices the secret took.
 *
 * NOTE: this kind of attack is NOT detectable by instruction-level analyzers
 * (no DIV, no JCC).  We include it as a *known limitation* test case:
 * the analyzer should report 0 violations here, but the code IS vulnerable.
 * This trains us to surface a "limitations" warning rather than a false-clean.
 *
 * Ground truth: nothing the analyzer can detect (label "limitation_no_signal")
 */

#include <stdint.h>

extern const uint32_t Te0[256];   /* in real AES, defined elsewhere */

void aes_subbytes_table(uint32_t state[4], const uint8_t key[16]) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = (state[i] >> 24) ^ key[i*4 + 0];
        uint8_t s1 = (state[i] >> 16) ^ key[i*4 + 1];
        uint8_t s2 = (state[i] >>  8) ^ key[i*4 + 2];
        uint8_t s3 =  state[i]        ^ key[i*4 + 3];
        /* VULNERABLE (cache timing): table indices are secret. */
        state[i] = Te0[s0] ^ Te0[s1] ^ Te0[s2] ^ Te0[s3];
    }
}
