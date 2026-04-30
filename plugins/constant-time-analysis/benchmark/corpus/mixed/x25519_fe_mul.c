/*
 * Curve25519 field-element multiplication transcribed from BoringSSL's
 * fe25519 reference implementation (donna64).  All arithmetic on the
 * 5-limb representation; no branches, no division, no table lookups.
 *
 * Source: https://github.com/google/boringssl/blob/main/third_party/fiat/curve25519_64.h
 *
 * Ground truth: 0 real timing leaks.
 * Any branches the analyzer flags are loop-counter operations.
 */

#include <stdint.h>

typedef uint64_t fe[5];
typedef unsigned __int128 uint128_t;

void fe_mul(fe out, const fe a, const fe b) {
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
    uint128_t r0 = (uint128_t)a0 * b0
                 + (uint128_t)a1 * b4 * 19
                 + (uint128_t)a2 * b3 * 19
                 + (uint128_t)a3 * b2 * 19
                 + (uint128_t)a4 * b1 * 19;
    uint128_t r1 = (uint128_t)a0 * b1
                 + (uint128_t)a1 * b0
                 + (uint128_t)a2 * b4 * 19
                 + (uint128_t)a3 * b3 * 19
                 + (uint128_t)a4 * b2 * 19;
    uint128_t r2 = (uint128_t)a0 * b2
                 + (uint128_t)a1 * b1
                 + (uint128_t)a2 * b0
                 + (uint128_t)a3 * b4 * 19
                 + (uint128_t)a4 * b3 * 19;
    uint128_t r3 = (uint128_t)a0 * b3
                 + (uint128_t)a1 * b2
                 + (uint128_t)a2 * b1
                 + (uint128_t)a3 * b0
                 + (uint128_t)a4 * b4 * 19;
    uint128_t r4 = (uint128_t)a0 * b4
                 + (uint128_t)a1 * b3
                 + (uint128_t)a2 * b2
                 + (uint128_t)a3 * b1
                 + (uint128_t)a4 * b0;
    /* Branchless reduction below 2^51. */
    const uint64_t mask = (1ULL << 51) - 1;
    uint64_t c;
    c = (uint64_t)(r0 >> 51); r1 += c; r0 &= mask;
    c = (uint64_t)(r1 >> 51); r2 += c; r1 &= mask;
    c = (uint64_t)(r2 >> 51); r3 += c; r2 &= mask;
    c = (uint64_t)(r3 >> 51); r4 += c; r3 &= mask;
    c = (uint64_t)(r4 >> 51); r0 += c * 19; r4 &= mask;
    c = r0 >> 51; r1 += c; r0 &= mask;
    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
}
