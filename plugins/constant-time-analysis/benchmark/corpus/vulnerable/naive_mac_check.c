/*
 * Naive MAC-check pattern — uses libc memcmp on a secret value vs. expected.
 *
 * Background: Standard memcmp is permitted to early-exit on the first
 * differing byte. Comparing a computed MAC to an attacker-supplied one with
 * memcmp leaks the position of the first mismatch, allowing a byte-at-a-time
 * forgery oracle (the well-known authentication-bypass timing pattern).
 *
 * Ground-truth label: VULNERABLE.
 *  - memcmp(mac, expected, 32) on secret bytes    -> memcmp_on_secret
 *  - if (cmp == 0) ...                            -> branch_on_secret
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int naive_authenticate(const uint8_t *computed_mac,
                       const uint8_t *received_mac, size_t len) {
  /* VIOLATION: variable-time memcmp on secret-derived buffer. */
  if (memcmp(computed_mac, received_mac, len) == 0) {  /* memcmp_on_secret */
    return 1;  /* accept */
  }
  return 0;
}

/* Same anti-pattern with strcmp, sometimes used for API tokens. */
int naive_token_check(const char *received, const char *expected) {
  return strcmp(received, expected) == 0;             /* strcmp_on_secret */
}
