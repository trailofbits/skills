/* Session lifecycle.
 *
 * The session owns rx_buf/rx_len/rx_cap. Nothing outside frame.c and reassembly.c
 * writes rx_len, and both keep rx_len <= rx_cap.
 *
 * A session also owns one instance each of the subsystems added alongside the
 * original relay/session/frame/reassembly/channel core: a retransmit timer wheel
 * (timer.c), a session-scoped emergency credit scheduler plus four per-class credit
 * pools (credit.c), a telemetry counter block (stats.c) and an out-of-order fragment
 * cache (reasm_oo.c). All four are created in session_init() and torn down in
 * session_destroy(), in the same order every time, so a partially-initialised
 * session is never handed back to a caller: any allocation failure during init
 * unwinds everything allocated before it and returns PL_ERR_NOMEM.
 */

#include "relay.h"

#include <stdlib.h>
#include <string.h>

static session_t *g_sessions[MAX_SESSIONS];
static uint32_t g_active_bitmap = 0;

session_t *session_create(uint16_t id) {
  session_t *s;

  if (id >= MAX_SESSIONS) {
    return NULL;
  }
  s = (session_t *)calloc(1, sizeof(*s));
  if (s == NULL) {
    return NULL;
  }
  s->id = id;
  if (session_init(s) != PL_OK) {
    free(s);
    return NULL;
  }
  g_sessions[id] = s;
  g_active_bitmap |= (uint32_t)1u << id;
  return s;
}

int session_init(session_t *s) {
  if (s == NULL) {
    return PL_ERR;
  }
  s->rx_cap = FRAME_MAX;
  s->rx_buf = (uint8_t *)calloc(1, s->rx_cap);
  if (s->rx_buf == NULL) {
    return PL_ERR_NOMEM;
  }
  s->rx_len = 0;
  s->arena = arena_create();
  if (s->arena == NULL) {
    free(s->rx_buf);
    s->rx_buf = NULL;
    return PL_ERR_NOMEM;
  }
  s->intern = intern_create();
  if (s->intern == NULL) {
    arena_destroy(s->arena);
    s->arena = NULL;
    free(s->rx_buf);
    s->rx_buf = NULL;
    return PL_ERR_NOMEM;
  }
  s->timers = timer_wheel_create();
  if (s->timers == NULL) {
    intern_destroy(s->intern);
    s->intern = NULL;
    arena_destroy(s->arena);
    s->arena = NULL;
    free(s->rx_buf);
    s->rx_buf = NULL;
    return PL_ERR_NOMEM;
  }
  credit_init(&s->credit);
  credit_pools_init(s);
  stats_init(&s->stats);
  reasm_oo_init(&s->oo);
  s->channel_count = 0;
  s->retry_depth = 0;
  s->active = 1;
  codec_init_all();
  return PL_OK;
}

session_t *session_lookup(uint16_t id) {
  if (id >= MAX_SESSIONS) {
    return NULL;
  }
  return g_sessions[id];
}

/* Callers reach this only after testing the active bitmap, so session_lookup cannot
 * return NULL here; the check is kept for the benefit of future callers. */
session_t *session_lookup_checked(uint16_t id) {
  session_t *s;

  if ((g_active_bitmap & ((uint32_t)1u << (id & 31))) == 0) {
    return NULL;
  }
  s = session_lookup(id);
  return s;
}

/* Copy a peer name out of a control message. The stored name is always terminated. */
int session_set_peer_name(session_t *s, const char *raw, size_t raw_len) {
  if (s == NULL || raw == NULL) {
    return PL_ERR;
  }
  if (raw_len >= sizeof(s->peer_name)) {
    return PL_ERR_LIMIT;
  }
  memset(s->peer_name, 0, sizeof(s->peer_name));
  memcpy(s->peer_name, raw, raw_len);
  s->peer_name[raw_len] = '\0';
  log_write("peer %s", s->peer_name);
  return PL_OK;
}

int session_reserve_rx(session_t *s, size_t need) {
  if (s == NULL) {
    return PL_ERR;
  }
  if (need > s->rx_cap) {
    return PL_ERR_LIMIT;
  }
  return PL_OK;
}

/* How many bytes of window credit remain for a channel at `off` of a `len`-byte
 * transfer. Both off and len come off the wire. */
int session_window_credit(session_t *s, uint16_t chan_id, uint32_t off, uint32_t len) {
  channel_t *chan;
  uint32_t total;

  if (s == NULL) {
    return PL_ERR;
  }
  chan = channel_find(s, chan_id);
  if (chan == NULL) {
    return PL_ERR_NO_CHANNEL;
  }
  /* Bound each operand before adding them: off and len are both 32-bit wire values
   * and their sum wraps. */
  if (off > FRAME_MAX || len > FRAME_MAX) {
    return PL_ERR_LIMIT;
  }
  total = off + len;
  if (total > s->rx_cap) {
    return PL_ERR_LIMIT;
  }
  if (len > sizeof(s->scratch)) {
    return PL_ERR_LIMIT;
  }
  memcpy(s->scratch, s->rx_buf + off, len);
  return (int)(chan->window - chan->pending_acks);
}

/* Teardown. Every cleanup call's result is checked; a failure in any of them leaves
 * the session in a state the caller has to know about. */
int session_destroy(session_t *s) {
  int rc = PL_OK;

  if (s == NULL) {
    return PL_ERR;
  }
  if (channel_close_all(s) != PL_OK) {
    rc = PL_ERR;
  }
  if (arena_reset(s->arena) != PL_OK) {
    rc = PL_ERR;
  }
  if (intern_clear(s->intern) != PL_OK) {
    rc = PL_ERR;
  }
  if (log_flush() != PL_OK) {
    rc = PL_ERR;
  }
  if (codec_table_reset() != PL_OK) {
    rc = PL_ERR;
  }

  arena_destroy(s->arena);
  s->arena = NULL;
  intern_destroy(s->intern);
  s->intern = NULL;
  timer_wheel_destroy(s->timers);
  s->timers = NULL;
  credit_pools_reclaim_all(s);
  free(s->rx_buf);
  s->rx_buf = NULL;
  s->rx_len = 0;
  s->rx_cap = 0;
  s->active = 0;
  if (s->id < MAX_SESSIONS) {
    g_sessions[s->id] = NULL;
    g_active_bitmap &= ~((uint32_t)1u << s->id);
  }
  return rc;
}
