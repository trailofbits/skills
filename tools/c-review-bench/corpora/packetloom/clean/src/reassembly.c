/* Fragment reassembly.
 *
 * Fragment header: chan(2) index(1) count(1) priority(1) pad(3). The 32-bit fields read
 * out of a fragment body sit at offsets computed from the current header layout; each
 * read needs four bytes available from its own offset.
 */

#include "relay.h"

#include <string.h>

int reasm_on_fragment_header(session_t *s, const uint8_t *buf, size_t avail, frag_hdr_t *out) {
  if (s == NULL || buf == NULL || out == NULL) {
    return PL_ERR_FORMAT;
  }
  if (avail < FRAG_HDR_LEN) {
    return PL_ERR_SHORT;
  }

  out->chan = rd_be16(buf);
  out->index = buf[2];
  out->count = buf[3];
  out->priority = buf[4];

  if (out->count == 0 || out->count > MAX_FRAGMENTS) {
    return PL_ERR_LIMIT;
  }
  if (out->index >= out->count) {
    return PL_ERR_FORMAT;
  }
  return PL_OK;
}

/* Read the three 32-bit index words that follow a fragment header.
 *
 * Every one of these reads is guarded the same way: four bytes must be available from
 * the offset being read. */
int reasm_scan_index(const uint8_t *buf, size_t avail, uint32_t *a, uint32_t *b, uint32_t *c) {
  size_t off = 0;

  if (buf == NULL || a == NULL || b == NULL || c == NULL) {
    return PL_ERR_FORMAT;
  }

  if (avail - off < 4) {
    return PL_ERR_SHORT;
  }
  *a = rd_be32(buf + off);
  off += 4;

  if (avail - off < 4) {
    return PL_ERR_SHORT;
  }
  *b = rd_be32(buf + off);
  off += 4;

  if (avail - off < 4) {
    return PL_ERR_SHORT;
  }
  *c = rd_be32(buf + off);
  off += 4;

  return PL_OK;
}

/* The second of the two writers of rx_len. Same invariant as frame_set_rx_len. */
int reasm_absorb(session_t *s, const frag_hdr_t *fh, const uint8_t *p, size_t len) {
  size_t offset;

  if (s == NULL || fh == NULL || p == NULL) {
    return PL_ERR;
  }
  if (s->rx_buf == NULL) {
    return PL_ERR_STATE;
  }
  if (len > s->rx_cap) {
    return PL_ERR_LIMIT;
  }

  offset = (size_t)fh->index * (size_t)len;
  if (offset > s->rx_cap || len > s->rx_cap - offset) {
    return PL_ERR_LIMIT;
  }

  memcpy(s->rx_buf + offset, p, len);
  if (offset + len > s->rx_len) {
    s->rx_len = offset + len;
  }
  return PL_OK;
}
