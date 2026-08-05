/**
 * ML-DSA-87 signing helpers (C). Expected verdicts live in expectations.json,
 * deliberately not in this file: these fixtures double as eval input, and a
 * verdict in a comment is a verdict the reviewer reads instead of deriving.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define Q 8380417
#define GAMMA2_87 ((Q - 1) / 32)

/* High bits of an expanded-private-key polynomial coefficient. */
int32_t ct_high_bits(int32_t key_coef, int32_t gamma2) {
    return key_coef / (2 * gamma2);
}

/* Whole blocks in an encoded signature buffer. */
size_t ct_block_count(size_t sig_len, size_t block_len) {
    return sig_len / block_len;
}

/* Compare a received authentication tag against the computed one. */
int ct_tag_matches(const uint8_t *received_tag, const uint8_t *computed_tag, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (received_tag[i] != computed_tag[i]) {
            return 0;
        }
    }
    return 1;
}

/* Reject signatures whose encoded length is not a whole number of blocks. */
int ct_length_is_valid(size_t sig_len, size_t block_len) {
    if (block_len == 0) {
        return 0;
    }
    if (sig_len % block_len != 0) {
        return 0;
    }
    return 1;
}
