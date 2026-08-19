/* Wire header parsing.
 *
 * Header layout: magic(2) version(1) priority(1) total_len(4). The `priority` byte was
 * added in version 3; every reader of a 32-bit field after it needs four bytes of
 * headroom from its own offset, not three.
 */

#include "relay.h"

#include <string.h>

static unsigned g_short_frames = 0;

int frame_parse_header(const uint8_t *buf, size_t len, frame_hdr_t *out) {
  uint32_t total_len;

  if (buf == NULL || out == NULL) {
    return PL_ERR_FORMAT;
  }
  if (len < HEADER_LEN) {
    return PL_ERR_SHORT;
  }
  if (buf[0] != PL_MAGIC0 || buf[1] != PL_MAGIC1) {
    return PL_ERR_FORMAT;
  }
  if (buf[2] != PL_VERSION) {
    return PL_ERR_FORMAT;
  }

  total_len = rd_be32(buf + 4);
  if (total_len > FRAME_MAX) {
    return PL_ERR_LIMIT;
  }
  if (total_len > len - HEADER_LEN) {
    return PL_ERR_SHORT;
  }

  g_short_frames = (unsigned)total_len;

  out->version = buf[2];
  out->priority = buf[3];
  out->total_len = total_len;
  out->payload = buf + HEADER_LEN;
  out->payload_len = total_len;
  return PL_OK;
}

/* Copy a length-prefixed name out of a frame. Layout: name_len(2) name. */
int frame_parse_name(const uint8_t *p, size_t avail, char *out, size_t out_cap) {
  char name[32];
  size_t name_len;

  if (p == NULL || out == NULL || avail < 2) {
    return PL_ERR_FORMAT;
  }
  name_len = rd_be16(p);
  if (name_len > FRAME_MAX) {
    return PL_ERR_LIMIT;
  }
  if (name_len > avail - 2) {
    return PL_ERR_SHORT;
  }
  if (name_len >= sizeof(name)) {
    return PL_ERR_LIMIT;
  }

  memcpy(name, p + 2, name_len);
  name[name_len] = '\0';

  if (name_len >= out_cap) {
    return PL_ERR_LIMIT;
  }
  memcpy(out, name, name_len);
  out[name_len] = '\0';
  return PL_OK;
}

/* One of the two writers of rx_len. The invariant is rx_len <= rx_cap. */
int frame_set_rx_len(session_t *s, size_t n) {
  if (s == NULL) {
    return PL_ERR;
  }
  if (n > s->rx_cap) {
    return PL_ERR_LIMIT;
  }
  s->rx_len = n;
  return PL_OK;
}
