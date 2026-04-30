/*
 * Extracted from libsodium crypto_stream/chacha20/ref/chacha20_ref.c —
 * keysetup + the inner block of chacha20_encrypt_bytes (one 64-byte block).
 * Source: https://raw.githubusercontent.com/jedisct1/libsodium/master/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
 *
 * Ground-truth label: CLEAN (with expected false positives).
 *
 * The keysetup loads the public sigma constants and then 8 LE-32 words from
 * `k`. The block function does 20 rounds of ARX (add-rotate-xor) with no
 * data-dependent branching.
 *
 * EXPECTED FALSE POSITIVES:
 *  - `for (i = 20; i > 0; i -= 2)` — public loop bound.
 *  - Conditional copy `if (bytes < 64)` — `bytes` is PUBLIC plaintext length.
 */

#include <stdint.h>
#include <string.h>

#define U32C(v) (v##U)
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))
#define ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w)  ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))

#define LOAD32_LE(p) \
  ((uint32_t)((p)[0]) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

#define QUARTERROUND(a, b, c, d) \
  a = PLUS(a, b); d = ROTATE(XOR(d, a), 16); \
  c = PLUS(c, d); b = ROTATE(XOR(b, c), 12); \
  a = PLUS(a, b); d = ROTATE(XOR(d, a),  8); \
  c = PLUS(c, d); b = ROTATE(XOR(b, c),  7);

struct chacha_ctx {
  uint32_t input[16];
};
typedef struct chacha_ctx chacha_ctx;

static void chacha_keysetup(chacha_ctx *ctx, const uint8_t *k) {
  ctx->input[0]  = U32C(0x61707865);
  ctx->input[1]  = U32C(0x3320646e);
  ctx->input[2]  = U32C(0x79622d32);
  ctx->input[3]  = U32C(0x6b206574);
  ctx->input[4]  = LOAD32_LE(k +  0);
  ctx->input[5]  = LOAD32_LE(k +  4);
  ctx->input[6]  = LOAD32_LE(k +  8);
  ctx->input[7]  = LOAD32_LE(k + 12);
  ctx->input[8]  = LOAD32_LE(k + 16);
  ctx->input[9]  = LOAD32_LE(k + 20);
  ctx->input[10] = LOAD32_LE(k + 24);
  ctx->input[11] = LOAD32_LE(k + 28);
}

/* One full 20-round ChaCha20 block. */
void chacha20_block(chacha_ctx *ctx, uint8_t out[64]) {
  uint32_t x0 = ctx->input[0],  x1 = ctx->input[1];
  uint32_t x2 = ctx->input[2],  x3 = ctx->input[3];
  uint32_t x4 = ctx->input[4],  x5 = ctx->input[5];
  uint32_t x6 = ctx->input[6],  x7 = ctx->input[7];
  uint32_t x8 = ctx->input[8],  x9 = ctx->input[9];
  uint32_t x10 = ctx->input[10], x11 = ctx->input[11];
  uint32_t x12 = ctx->input[12], x13 = ctx->input[13];
  uint32_t x14 = ctx->input[14], x15 = ctx->input[15];

  /* Public loop bound. */
  for (int i = 20; i > 0; i -= 2) {
    QUARTERROUND(x0, x4, x8, x12)
    QUARTERROUND(x1, x5, x9, x13)
    QUARTERROUND(x2, x6, x10, x14)
    QUARTERROUND(x3, x7, x11, x15)
    QUARTERROUND(x0, x5, x10, x15)
    QUARTERROUND(x1, x6, x11, x12)
    QUARTERROUND(x2, x7, x8, x13)
    QUARTERROUND(x3, x4, x9, x14)
  }

  uint32_t s[16] = {x0, x1, x2, x3, x4, x5, x6, x7,
                    x8, x9, x10, x11, x12, x13, x14, x15};
  for (int i = 0; i < 16; i++) {
    s[i] = PLUS(s[i], ctx->input[i]);
    out[i*4 + 0] = (uint8_t)(s[i] >>  0);
    out[i*4 + 1] = (uint8_t)(s[i] >>  8);
    out[i*4 + 2] = (uint8_t)(s[i] >> 16);
    out[i*4 + 3] = (uint8_t)(s[i] >> 24);
  }
}
