/* Out-of-order fragment cache — the fast-path reassembly strategy.
 *
 * The ordinary path (reassembly.c) absorbs a fragment directly into the session's
 * rx_buf at an offset computed from its index, tolerating any arrival order on its
 * own. This module exists for a different transport: fragments delivered out-of-band
 * over the local control channel, in small bursts, without the enclosing frame
 * header. Each one is staged in a fixed-size cache slot and then handed to
 * reasm_absorb() — the same function the ordinary path uses — so rx_len still has
 * exactly one invariant regardless of which strategy staged the bytes.
 */

#include "relay.h"

#include <string.h>

void reasm_oo_init(reasm_oo_t *oo) {
  if (oo == NULL) {
    return;
  }
  memset(oo, 0, sizeof(*oo));
}

int reasm_oo_stash(reasm_oo_t *oo, uint8_t index, const uint8_t *p, size_t len) {
  size_t i;
  int free_slot = -1;

  if (oo == NULL || p == NULL) {
    return PL_ERR;
  }
  if (len > OO_SLOT_CAP) {
    return PL_ERR_LIMIT;
  }
  for (i = 0; i < REASM_OO_SLOTS; i++) {
    if (oo->slots[i].used && oo->slots[i].index == index) {
      free_slot = (int)i; /* replace an existing stash for the same index */
      break;
    }
    if (!oo->slots[i].used && free_slot < 0) {
      free_slot = (int)i;
    }
  }
  if (free_slot < 0) {
    return PL_ERR_LIMIT; /* cache full */
  }
  copy_field(oo->slots[free_slot].data, sizeof(oo->slots[free_slot].data), p, len);
  oo->slots[free_slot].used = 1;
  oo->slots[free_slot].index = index;
  oo->slots[free_slot].len = (uint16_t)len;
  return PL_OK;
}

/* Drain every stashed fragment into the ordinary reassembly path. */
static int reasm_oo_flush(reasm_oo_t *oo, session_t *s, uint16_t chan_id) {
  size_t i;

  if (oo == NULL || s == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < REASM_OO_SLOTS; i++) {
    frag_hdr_t fh;
    int rc;

    if (!oo->slots[i].used) {
      continue;
    }
    memset(&fh, 0, sizeof(fh));
    fh.chan = chan_id;
    fh.index = oo->slots[i].index;
    fh.count = MAX_FRAGMENTS;
    rc = reasm_absorb(s, &fh, oo->slots[i].data, oo->slots[i].len);
    oo->slots[i].used = 0;
    if (rc != PL_OK) {
      return rc;
    }
  }
  return PL_OK;
}

/* Copy a stashed fragment back out for debugging, without draining it from the
 * cache. The caller's buffer is not guaranteed to be OO_SLOT_CAP bytes, so the
 * stashed length must be checked against out_cap before the copy. */
int reasm_oo_peek(const reasm_oo_t *oo, uint8_t index, uint8_t *out, size_t out_cap) {
  size_t i;

  if (oo == NULL || out == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < REASM_OO_SLOTS; i++) {
    if (oo->slots[i].used && oo->slots[i].index == index) {
      if (oo->slots[i].len > out_cap) {
        return PL_ERR_LIMIT;
      }
      memcpy(out, oo->slots[i].data, oo->slots[i].len);
      return PL_OK;
    }
  }
  return PL_ERR_NO_CHANNEL;
}

int reasm_fast_absorb(session_t *s, uint16_t chan_id, uint8_t index, const uint8_t *p, size_t len) {
  int rc;

  if (s == NULL || p == NULL) {
    return PL_ERR;
  }
  if (index >= MAX_FRAGMENTS) {
    return PL_ERR_LIMIT;
  }
  rc = reasm_oo_stash(&s->oo, index, p, len);
  if (rc != PL_OK) {
    return rc;
  }
  return reasm_oo_flush(&s->oo, s, chan_id);
}
