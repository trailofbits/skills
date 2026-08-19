/* Retransmit backoff policy.
 *
 * A fixed table of per-attempt delays, in ticks of the timer wheel (timer.c). The
 * table has BACKOFF_STEPS entries; every caller must clamp an attempt count to
 * BACKOFF_STEPS - 1 before indexing it, because attempt counts are not otherwise
 * bounded — a channel that keeps missing acks keeps incrementing its own counter.
 */

#include "relay.h"

#define BACKOFF_STEPS 6

static const unsigned g_backoff_ticks[BACKOFF_STEPS] = {1, 2, 4, 8, 8, 8};

unsigned backoff_next(unsigned attempt) {
  if (attempt >= BACKOFF_STEPS) {
    attempt = BACKOFF_STEPS - 1;
  }
  return g_backoff_ticks[attempt];
}

unsigned backoff_max_attempt(void) { return BACKOFF_STEPS - 1; }
