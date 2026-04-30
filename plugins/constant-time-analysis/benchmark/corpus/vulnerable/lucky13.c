/*
 * Lucky Thirteen (2013) pattern - synthetic.
 *
 * The original CBC padding-validation loop runs HMAC over a number of bytes
 * that depends on the (secret) padding length.  Even if the comparison itself
 * is constant-time, the LOOP COUNT is secret.  Network timing reveals it.
 *
 * Reference: AlFardan & Paterson, "Lucky Thirteen", IEEE S&P 2013.
 *
 * Ground truth: lines 22-26 contain secret-dependent branch (the padding loop).
 *               line 32: unsafe memcmp on MAC (early-exit timing leak).
 */

#include <stdint.h>
#include <string.h>

int lucky13_validate_padding(const uint8_t *plaintext, int len) {
    int padding_len = plaintext[len - 1];      /* secret: depends on plaintext */
    if (padding_len > len - 1) return -1;      /* public bound check, not flag */

    /* VULNERABLE: branch count depends on secret padding_len. */
    for (int i = 0; i < padding_len; i++) {
        if (plaintext[len - 1 - i] != padding_len) {
            return -1;                          /* early exit on mismatch */
        }
    }
    return len - padding_len - 1;
}

/* VULNERABLE: memcmp is variable-time on first mismatch. */
int verify_mac(const uint8_t *received, const uint8_t *expected, size_t n) {
    /* compiler implements memcmp as a loop with conditional branch */
    return memcmp(received, expected, n) == 0;
}
