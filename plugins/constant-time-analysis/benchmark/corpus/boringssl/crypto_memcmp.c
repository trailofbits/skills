/*
 * Extracted from BoringSSL crypto/mem.cc (CRYPTO_memcmp).
 * Source: https://raw.githubusercontent.com/google/boringssl/main/crypto/mem.cc
 *
 * Designed to be constant-time: every byte of both inputs is read in a
 * fixed-iteration loop; the early-exit pattern of libc memcmp is removed.
 * The only branch / loop bound is `len`, which is PUBLIC.
 */

#include <stddef.h>
#include <stdint.h>

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len) {
    const uint8_t *a = (const uint8_t *)in_a;
    const uint8_t *b = (const uint8_t *)in_b;
    uint8_t x = 0;

    for (size_t i = 0; i < len; i++) {
        x |= a[i] ^ b[i];
    }

    return x;
}
