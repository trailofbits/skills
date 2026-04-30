/*
 * Extracted from libsodium src/libsodium/sodium/utils.c.
 * Source: https://raw.githubusercontent.com/jedisct1/libsodium/master/src/libsodium/sodium/utils.c
 *
 * sodium_memcmp / sodium_is_zero: standard libsodium constant-time helpers.
 * `volatile` qualifiers prevent the compiler from inserting early exits.
 * The only loop bound is `len`/`nlen` (public).
 */

#include <stddef.h>
#include <stdint.h>

int sodium_memcmp(const void *const b1_, const void *const b2_, size_t len) {
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
    size_t i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

int sodium_is_zero(const unsigned char *n, const size_t nlen) {
    size_t i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}
