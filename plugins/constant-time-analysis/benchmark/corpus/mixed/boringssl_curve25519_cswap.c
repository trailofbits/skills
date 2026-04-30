/*
 * Extracted from BoringSSL crypto/curve25519/curve25519.cc — fe_cswap and fe_cmov.
 * Source: https://raw.githubusercontent.com/google/boringssl/master/crypto/curve25519/curve25519.cc
 *
 * Ground-truth label: CLEAN (with expected false positives).
 *
 * `fe_cswap` and `fe_cmov` are the canonical X25519 ladder primitives. They
 * conditionally swap two field elements without branching: a 0/1 condition is
 * negated to 0x000... or 0xFFF..., AND-masked, then XOR-applied. The loop
 * bound FE_NUM_LIMBS is a public compile-time constant.
 *
 * EXPECTED FALSE POSITIVES:
 *  - `for (i = 0; i < FE_NUM_LIMBS; i++)` — FE_NUM_LIMBS is PUBLIC.
 *  - `b = 0 - b;` may look like an arithmetic operation on a "swap-bit"
 *    derived from secret bits, but the resulting value is then ONLY used as
 *    a bit-mask; no division or branch follows.
 */

#include <stdint.h>

#define FE_NUM_LIMBS 5
typedef uint64_t fe_limb_t;
typedef struct { fe_limb_t v[FE_NUM_LIMBS]; } fe;
typedef struct { fe_limb_t v[FE_NUM_LIMBS]; } fe_loose;

/* Replace (f, g) with (g, f) if b == 1; leave them as-is if b == 0.
 * Precondition: b in {0, 1}. */
void fe_cswap(fe *f, fe *g, fe_limb_t b) {
  b = 0 - b;
  for (unsigned i = 0; i < FE_NUM_LIMBS; i++) {
    fe_limb_t x = f->v[i] ^ g->v[i];
    x &= b;
    f->v[i] ^= x;
    g->v[i] ^= x;
  }
}

/* Replace f with g if b == 1; leave f if b == 0. */
void fe_cmov(fe_loose *f, const fe_loose *g, fe_limb_t b) {
  b = 0 - b;
  for (unsigned i = 0; i < FE_NUM_LIMBS; i++) {
    fe_limb_t x = f->v[i] ^ g->v[i];
    x &= b;
    f->v[i] ^= x;
  }
}
