/*
 * Extracted from BoringSSL crypto/chacha/chacha.cc — the ChaCha20 quarter-round
 * and CRYPTO_hchacha20 entry point.
 * Source: https://raw.githubusercontent.com/google/boringssl/master/crypto/chacha/chacha.cc
 *
 * Ground-truth label: CLEAN (with expected false positives).
 *
 * The body uses only +, ^, rotate, and array indexing by COMPILE-TIME-CONSTANT
 * indices — perfectly constant-time over secret state.
 *
 * EXPECTED FALSE POSITIVES (do not count as real findings):
 *  - The `for (size_t i = 0; i < 20; i += 2)` loop bound 20 is a public
 *    constant; flagging it as "loop bound depends on data" would be wrong.
 *  - memcpy with sizeof(...) constants — public size, not secret.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t CRYPTO_rotl_u32(uint32_t v, int n) {
  return (v << n) | (v >> (32 - n));
}

#define QUARTERROUND(a, b, c, d)             \
  x[a] += x[b];                              \
  x[d] = CRYPTO_rotl_u32(x[d] ^ x[a], 16);   \
  x[c] += x[d];                              \
  x[b] = CRYPTO_rotl_u32(x[b] ^ x[c], 12);   \
  x[a] += x[b];                              \
  x[d] = CRYPTO_rotl_u32(x[d] ^ x[a], 8);    \
  x[c] += x[d];                              \
  x[b] = CRYPTO_rotl_u32(x[b] ^ x[c], 7)

static const uint8_t sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                  '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};

void CRYPTO_hchacha20(uint8_t out[32], const uint8_t key[32],
                      const uint8_t nonce[16]) {
  uint32_t x[16];
  memcpy(x, sigma, sizeof(sigma));
  memcpy(&x[4], key, 32);
  memcpy(&x[12], nonce, 16);

  /* Loop bound 20 is a PUBLIC compile-time constant. */
  for (size_t i = 0; i < 20; i += 2) {
    QUARTERROUND(0, 4, 8, 12);
    QUARTERROUND(1, 5, 9, 13);
    QUARTERROUND(2, 6, 10, 14);
    QUARTERROUND(3, 7, 11, 15);
    QUARTERROUND(0, 5, 10, 15);
    QUARTERROUND(1, 6, 11, 12);
    QUARTERROUND(2, 7, 8, 13);
    QUARTERROUND(3, 4, 9, 14);
  }

  memcpy(out, &x[0], sizeof(uint32_t) * 4);
  memcpy(&out[16], &x[12], sizeof(uint32_t) * 4);
}
