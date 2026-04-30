/*
 * Extracted from mbedTLS library/constant_time.c.
 * Source: https://raw.githubusercontent.com/Mbed-TLS/mbedtls/master/library/constant_time.c
 *
 * mbedtls_ct_memcmp + mbedtls_ct_memcmp_partial.  All loop bounds are
 * public (n, skip_head, skip_tail).  All conditional logic uses bitwise
 * mask combinations rather than branches.
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

int mbedtls_ct_memcmp(const void *a, const void *b, size_t n) {
    size_t i = 0;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    uint32_t diff = 0;

    for (; i < n; i++) {
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    /* Cast-safe non-zero-iff-diff-non-zero. */
    return (int) ((diff & 0xffff) | (diff >> 16));
}

int mbedtls_ct_memcmp_partial(const void *a, const void *b, size_t n,
                              size_t skip_head, size_t skip_tail) {
    unsigned int diff = 0;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    size_t valid_end = n - skip_tail;

    for (size_t i = 0; i < n; i++) {
        unsigned char x = A[i], y = B[i];
        unsigned int d = x ^ y;
        /* mask = (i >= skip_head) & (i < valid_end), built without branches */
        unsigned int ge = (unsigned int)-(int)(i >= skip_head);
        unsigned int lt = (unsigned int)-(int)(i < valid_end);
        unsigned int valid = ge & lt;
        diff |= d & valid;
    }
    return (int) diff;
}
