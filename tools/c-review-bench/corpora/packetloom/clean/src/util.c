/* Small shared helpers.
 *
 * copy_field() is deliberately unbounded: it is the inner-loop copy used by the
 * control decoders, and every caller has already validated `len` against the
 * destination capacity by the time it gets here. The `dst_cap` argument exists so a
 * caller can pass what it validated against and so the contract is visible at the
 * call site; it is not a second line of defence.
 *
 * CONTRACT: the caller MUST guarantee len <= dst_cap. This function does not check.
 */

#include "relay.h"

#include <string.h>

void copy_field(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t len) {
  (void)dst_cap;
  if (dst == NULL || src == NULL || len == 0) {
    return;
  }
  memcpy(dst, src, len);
}

uint32_t rd_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint16_t rd_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
