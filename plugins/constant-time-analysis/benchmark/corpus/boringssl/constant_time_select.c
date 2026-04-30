/*
 * Extracted from BoringSSL crypto/internal.h (constant-time select family).
 * Source: https://raw.githubusercontent.com/google/boringssl/main/crypto/internal.h
 *
 * These inline helpers form the canonical "constant-time" primitives used
 * throughout BoringSSL.  Every branch / division below is on a PUBLIC value
 * (loop counter or sizeof()), so a secret-aware analysis should report 0
 * vulnerabilities here.
 */

#include <stddef.h>
#include <stdint.h>

typedef uintptr_t crypto_word_t;

/* The compiler optimization barrier used by BoringSSL.  In production this
 * is implemented with inline asm; the analyzer only needs the C semantics. */
static inline crypto_word_t value_barrier_w(crypto_word_t a) {
    __asm__("" : "+r"(a) : /* no inputs */);
    return a;
}

/* constant_time_msb_w: replicate the MSB across the whole word. */
static inline crypto_word_t constant_time_msb_w(crypto_word_t a) {
    return 0u - (a >> (sizeof(a) * 8 - 1));
}

/* constant_time_lt_w: 0xff..f if a < b else 0. */
static inline crypto_word_t constant_time_lt_w(crypto_word_t a, crypto_word_t b) {
    return constant_time_msb_w(a ^ ((a ^ b) | ((a - b) ^ a)));
}

/* constant_time_ge_w: 0xff..f if a >= b else 0. */
static inline crypto_word_t constant_time_ge_w(crypto_word_t a, crypto_word_t b) {
    return ~constant_time_lt_w(a, b);
}

/* constant_time_is_zero_w: 0xff..f if a == 0 else 0. */
static inline crypto_word_t constant_time_is_zero_w(crypto_word_t a) {
    return constant_time_msb_w(~a & (a - 1));
}

/* constant_time_eq_w: 0xff..f if a == b else 0. */
static inline crypto_word_t constant_time_eq_w(crypto_word_t a, crypto_word_t b) {
    return constant_time_is_zero_w(a ^ b);
}

/* constant_time_select_w: (mask & a) | (~mask & b). */
static inline crypto_word_t constant_time_select_w(crypto_word_t mask,
                                                   crypto_word_t a,
                                                   crypto_word_t b) {
    mask = value_barrier_w(mask);
    return (mask & a) | (~mask & b);
}

/* constant_time_select_8: 8-bit variant. */
static inline uint8_t constant_time_select_8(crypto_word_t mask,
                                             uint8_t a, uint8_t b) {
    uint8_t m = (uint8_t)value_barrier_w(mask);
    return (m & a) | (~m & b);
}

/* Public-API wrapper so the file produces emitted code at -O2. */
crypto_word_t bench_select(crypto_word_t mask, crypto_word_t a, crypto_word_t b) {
    return constant_time_select_w(mask, a, b);
}

uint8_t bench_eq8(crypto_word_t a, crypto_word_t b) {
    return (uint8_t)constant_time_eq_w(a, b);
}
