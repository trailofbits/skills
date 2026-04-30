/*
 * ChaCha20 quarter-round and core, transcribed from DJB's reference
 * (libsodium chacha20_ref.c).  ChaCha20 is intentionally constant-time:
 *  * no data-dependent branches
 *  * no table lookups
 *  * no division
 * Loop counts are public (block size, key-stream length).
 *
 * Ground truth: 0 real timing leaks.  Any branches the analyzer flags
 * are loop-counter / length-bound checks (false positives).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7);

void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(x[ 0], x[ 4], x[ 8], x[12])
        QUARTERROUND(x[ 1], x[ 5], x[ 9], x[13])
        QUARTERROUND(x[ 2], x[ 6], x[10], x[14])
        QUARTERROUND(x[ 3], x[ 7], x[11], x[15])
        QUARTERROUND(x[ 0], x[ 5], x[10], x[15])
        QUARTERROUND(x[ 1], x[ 6], x[11], x[12])
        QUARTERROUND(x[ 2], x[ 7], x[ 8], x[13])
        QUARTERROUND(x[ 3], x[ 4], x[ 9], x[14])
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

/* CTR loop; the only conditional is `len` which is public. */
void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint32_t state[16]) {
    uint32_t block[16];
    uint32_t local[16];
    memcpy(local, state, sizeof(local));
    while (len >= 64) {
        chacha20_block(block, local);
        for (int i = 0; i < 64; i++)
            out[i] = in[i] ^ ((const uint8_t *)block)[i];
        local[12]++;            /* counter */
        out += 64; in += 64; len -= 64;
    }
    if (len) {
        chacha20_block(block, local);
        for (size_t i = 0; i < len; i++)
            out[i] = in[i] ^ ((const uint8_t *)block)[i];
    }
}
