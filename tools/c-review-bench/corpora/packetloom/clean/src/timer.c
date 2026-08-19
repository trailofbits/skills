/* Retransmit timer wheel.
 *
 * One bucket per tick offset. Arming a channel's retransmit timer writes a slot into
 * the bucket `delay` ticks ahead of the current cursor; ticking the wheel fires every
 * slot in the bucket the cursor is leaving, then advances by one. A fired timer whose
 * channel still has unacknowledged sends is re-armed (escalated) into a later bucket
 * rather than dropped, so a channel that keeps missing acks keeps retrying.
 */

#include "relay.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  uint16_t chan_id;
  uint8_t armed;
  uint8_t attempts;
} timer_slot_t;

struct timer_wheel_s {
  timer_slot_t buckets[TIMER_BUCKETS][TIMER_MAX_ARMED];
  uint8_t counts[TIMER_BUCKETS];
  unsigned cursor;
};

timer_wheel_t *timer_wheel_create(void) { return (timer_wheel_t *)calloc(1, sizeof(timer_wheel_t)); }

void timer_wheel_destroy(timer_wheel_t *tw) { free(tw); }

int timer_wheel_arm(timer_wheel_t *tw, uint16_t chan_id, unsigned delay) {
  unsigned idx;
  uint8_t i;

  if (tw == NULL) {
    return PL_ERR;
  }
  idx = (tw->cursor + delay) % TIMER_BUCKETS;
  for (i = 0; i < tw->counts[idx]; i++) {
    if (tw->buckets[idx][i].armed && tw->buckets[idx][i].chan_id == chan_id) {
      return PL_OK; /* already armed in this bucket */
    }
  }
  if (tw->counts[idx] >= TIMER_MAX_ARMED) {
    return PL_ERR_LIMIT;
  }
  tw->buckets[idx][tw->counts[idx]].chan_id = chan_id;
  tw->buckets[idx][tw->counts[idx]].armed = 1;
  tw->buckets[idx][tw->counts[idx]].attempts = 0;
  tw->counts[idx]++;
  return PL_OK;
}

int timer_wheel_cancel(timer_wheel_t *tw, uint16_t chan_id) {
  unsigned b;

  if (tw == NULL) {
    return PL_ERR;
  }
  for (b = 0; b < TIMER_BUCKETS; b++) {
    uint8_t i;
    for (i = 0; i < tw->counts[b]; i++) {
      if (tw->buckets[b][i].armed && tw->buckets[b][i].chan_id == chan_id) {
        uint8_t j;
        for (j = (uint8_t)(i + 1); j < tw->counts[b]; j++) {
          tw->buckets[b][j - 1] = tw->buckets[b][j];
        }
        tw->counts[b]--;
        return PL_OK;
      }
    }
  }
  return PL_ERR_NO_CHANNEL;
}

/* Re-arm a fired timer that still has work to do, `backoff_next(attempts)` buckets
 * further out than the one it just fired from — later each time it keeps missing
 * acks. */
static int timer_wheel_requeue(timer_wheel_t *tw, unsigned from_bucket, uint16_t chan_id,
                                uint8_t attempts) {
  unsigned delay;
  unsigned idx;

  delay = backoff_next(attempts);
  idx = (from_bucket + delay) % TIMER_BUCKETS;
  if (tw->counts[idx] >= TIMER_MAX_ARMED) {
    return PL_ERR_LIMIT;
  }
  tw->buckets[idx][tw->counts[idx]].chan_id = chan_id;
  tw->buckets[idx][tw->counts[idx]].armed = 1;
  tw->buckets[idx][tw->counts[idx]].attempts = (uint8_t)(attempts + 1);
  tw->counts[idx]++;
  return PL_OK;
}

int timer_wheel_tick(timer_wheel_t *tw, session_t *s) {
  unsigned cur;
  uint8_t i;

  if (tw == NULL || s == NULL) {
    return PL_ERR;
  }
  cur = tw->cursor;
  for (i = 0; i < tw->counts[cur]; i++) {
    channel_t *chan;

    if (!tw->buckets[cur][i].armed) {
      continue;
    }
    chan = channel_find(s, tw->buckets[cur][i].chan_id);
    if (chan != NULL && chan->pending_acks > 0) {
      relay_schedule_retry(s, chan->id);
      timer_wheel_requeue(tw, cur, chan->id, tw->buckets[cur][i].attempts);
    }
  }
  tw->counts[cur] = 0;
  tw->cursor = (cur + 1) % TIMER_BUCKETS;
  return PL_OK;
}
