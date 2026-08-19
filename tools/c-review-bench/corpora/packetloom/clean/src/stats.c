/* Telemetry counters.
 *
 * A fixed-size array of STATS_MAX_COUNTERS event counters, indexed by a small integer
 * id: stats_record() is the internal path, called with ids this file defines itself,
 * and stats_merge_snapshot() is the wire path, which accepts a peer-sent id.
 * stats_name_copy() turns a counter id back into its human-readable name, for a
 * diagnostic reply.
 */

#include "relay.h"

#include <string.h>

static const char *const g_counter_names[STATS_MAX_COUNTERS] = {
    "frame",   "control", "chan_open", "chan_close", "retry",       "credit",
    "option",  "fastfrag", "merge",    "decode",     "label_reject", "reset",
};

void stats_init(stats_t *st) {
  if (st == NULL) {
    return;
  }
  memset(st, 0, sizeof(*st));
}

int stats_record(stats_t *st, unsigned counter_id) {
  if (st == NULL) {
    return PL_ERR;
  }
  if (counter_id >= STATS_MAX_COUNTERS) {
    return PL_ERR_LIMIT;
  }
  st->counters[counter_id]++;
  return PL_OK;
}

/* A peer-sent snapshot: a sequence of (counter_id(1) delta_be32(4)) tuples, merged by
 * addition into the local counters. */
int stats_merge_snapshot(stats_t *st, const uint8_t *buf, size_t avail) {
  size_t off = 0;

  if (st == NULL || buf == NULL) {
    return PL_ERR;
  }
  while (off + 5 <= avail) {
    unsigned counter_id = buf[off];
    uint32_t delta = rd_be32(buf + off + 1);

    if (counter_id >= STATS_MAX_COUNTERS) {
      return PL_ERR_LIMIT;
    }
    st->counters[counter_id] += delta;
    off += 5;
  }
  return PL_OK;
}

int stats_dump(const stats_t *st, uint8_t *out, size_t out_cap) {
  uint8_t buf[STATS_MAX_COUNTERS * 4];
  size_t i;
  size_t total = sizeof(buf);

  if (st == NULL || out == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < STATS_MAX_COUNTERS; i++) {
    buf[i * 4 + 0] = (uint8_t)(st->counters[i] >> 24);
    buf[i * 4 + 1] = (uint8_t)(st->counters[i] >> 16);
    buf[i * 4 + 2] = (uint8_t)(st->counters[i] >> 8);
    buf[i * 4 + 3] = (uint8_t)(st->counters[i]);
  }
  if (total > out_cap) {
    return PL_ERR_LIMIT;
  }
  copy_field(out, out_cap, buf, total);
  return PL_OK;
}

/* The human-readable name of a counter, for a diagnostic control reply. The reply
 * buffer is caller-sized and may be shorter than the longest name in the table
 * ("label_reject", 13 bytes with the terminator), so the length has to be checked
 * before the copy. */
int stats_name_copy(unsigned counter_id, char *out, size_t out_cap) {
  size_t needed;

  if (out == NULL || counter_id >= STATS_MAX_COUNTERS) {
    return PL_ERR;
  }
  needed = strlen(g_counter_names[counter_id]) + 1;
  if (needed > out_cap) {
    return PL_ERR_LIMIT;
  }
  memcpy(out, g_counter_names[counter_id], needed);
  return PL_OK;
}
