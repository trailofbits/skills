/*
 * Reproduction of OpenSSL's canonical CRYPTO_memcmp implementation.
 * Reference (historical): crypto/cryptlib.c / crypto/o_str.c.
 *
 * This is the textbook constant-time byte comparator used in dozens of
 * crypto libraries.  The accumulator `x` is built unconditionally; the loop
 * bound `len` is public.  No branches, no table lookups on secrets.
 */

#include <stddef.h>
#include <stdint.h>

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len) {
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++) {
        x |= a[i] ^ b[i];
    }

    return x;
}
