/* Channel table, ack/window bookkeeping and id packing.
 *
 * Invariant, maintained by every writer of pending_acks: pending_acks <= window, and
 * window <= MAX_WINDOW. retry_slots is indexed by pending_acks, so a writer that skips
 * the bound writes past the end of the array.
 */

#include "relay.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

channel_t *channel_find(session_t *s, uint16_t chan_id) {
  size_t i;

  if (s == NULL) {
    return NULL;
  }
  for (i = 0; i < s->channel_count; i++) {
    if (s->channels[i] != NULL && s->channels[i]->id == chan_id) {
      return s->channels[i];
    }
  }
  return NULL;
}

/* Pack a channel id and its priority bit into the one-byte ack field.
 *
 * MAX_CHANNELS is 128, so the id needs seven bits and the flag gets the low one. */
uint8_t channel_pack_id(uint16_t chan_id, uint8_t flags) {
  return (uint8_t)(((chan_id & 0x7F) << 1) | (flags & 0x01));
}

uint16_t channel_unpack_id(uint8_t packed) { return (uint16_t)((packed >> 1) & 0x7F); }

int channel_open(session_t *s, const char *label, size_t label_len, channel_t **out) {
  channel_t *chan;
  int slot;

  if (s == NULL || label == NULL || out == NULL) {
    return PL_ERR;
  }
  if (s->channel_count >= MAX_CHANNELS) {
    return PL_ERR_LIMIT;
  }

  chan = arena_alloc(s->arena);
  if (chan == NULL) {
    chan = arena_recycle(s->arena);
  }
  if (chan == NULL) {
    return PL_ERR_NOMEM;
  }

  if (label_len >= LABEL_MAX) {
    /* Every exit path after the allocation must return the slot. */
    arena_free(s->arena, chan);
    return PL_ERR_LABEL_TOO_LONG;
  }

  chan->heap_label = (char *)malloc(label_len + 1);
  if (chan->heap_label == NULL) {
    arena_free(s->arena, chan);
    return PL_ERR_NOMEM;
  }
  memcpy(chan->heap_label, label, label_len);
  chan->heap_label[label_len] = '\0';

  memcpy(chan->label, label, label_len);
  chan->label[label_len] = '\0';
  chan->id = (uint16_t)s->channel_count;
  chan->flags = CH_FLAG_OPEN;
  chan->refcount = 1;
  chan->window = MAX_WINDOW;
  chan->pending_acks = 0;
  chan->ack_byte = channel_pack_id(chan->id, CH_FLAG_PRIORITY & 0x01);

  s->channels[s->channel_count++] = chan;

  slot = intern_add(s->intern, chan->label, label_len);
  if (slot >= 0) {
    log_field(s, slot, "open");
  }

  *out = chan;
  return PL_OK;
}

int channel_set_label(channel_t *chan, const char *new_label) {
  size_t n;

  if (chan == NULL || new_label == NULL) {
    return PL_ERR;
  }
  n = strlen(new_label);
  if (n >= sizeof(chan->label)) {
    return PL_ERR_LABEL_TOO_LONG;
  }
  memcpy(chan->label, new_label, n);
  chan->label[n] = '\0';
  return PL_OK;
}

int channel_send(session_t *s, channel_t *chan, uint16_t slot) {
  if (s == NULL || chan == NULL) {
    return PL_ERR;
  }
  chan->window = (uint16_t)(chan->window < MAX_WINDOW ? chan->window : MAX_WINDOW);
  if (chan->pending_acks >= chan->window) {
    return PL_ERR_LIMIT;
  }
  chan->retry_slots[chan->pending_acks++] = slot;
  return PL_OK;
}

int channel_on_ack(session_t *s, channel_t *chan, uint16_t slot) {
  uint16_t i;

  if (s == NULL || chan == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < chan->pending_acks; i++) {
    if (chan->retry_slots[i] == slot) {
      uint16_t j;
      for (j = (uint16_t)(i + 1); j < chan->pending_acks; j++) {
        chan->retry_slots[j - 1] = chan->retry_slots[j];
      }
      chan->pending_acks--;
      return PL_OK;
    }
  }
  if (chan->pending_acks >= chan->window) {
    return PL_ERR_LIMIT;
  }
  chan->retry_slots[chan->pending_acks++] = slot;
  return PL_OK;
}

/* Priority fast path: same bookkeeping as channel_send, reached from the priority
 * frame handler rather than from the ordinary send path. */
int channel_inject_control(session_t *s, channel_t *chan, uint16_t slot) {
  if (s == NULL || chan == NULL) {
    return PL_ERR;
  }
  if ((chan->flags & CH_FLAG_OPEN) == 0) {
    return PL_ERR_STATE;
  }
  if (chan->pending_acks >= chan->window) {
    return PL_ERR_LIMIT;
  }
  chan->retry_slots[chan->pending_acks++] = slot;
  chan->flags |= CH_FLAG_PRIORITY;
  return PL_OK;
}

int channel_close(session_t *s, uint16_t chan_id) {
  channel_t *chan;
  size_t i;

  chan = channel_find(s, chan_id);
  if (chan == NULL) {
    return PL_ERR_NO_CHANNEL;
  }

  /* Read everything needed off the heap label before releasing it. */
  if (chan->heap_label != NULL && chan->heap_label[0] == '\0') {
    chan->flags &= (uint8_t)~CH_FLAG_PRIORITY;
  }
  free(chan->heap_label);
  chan->heap_label = NULL;

  chan->flags = 0;
  chan->refcount = 0;
  for (i = 0; i < s->channel_count; i++) {
    if (s->channels[i] == chan) {
      s->channels[i] = s->channels[s->channel_count - 1];
      s->channels[s->channel_count - 1] = NULL;
      s->channel_count--;
      break;
    }
  }
  arena_free(s->arena, chan);
  return PL_OK;
}

int channel_close_all(session_t *s) {
  if (s == NULL) {
    return PL_ERR;
  }
  while (s->channel_count > 0) {
    channel_t *chan = s->channels[s->channel_count - 1];
    if (chan == NULL) {
      s->channel_count--;
      continue;
    }
    if (channel_close(s, chan->id) != PL_OK) {
      s->channel_count--;
    }
  }
  return PL_OK;
}
