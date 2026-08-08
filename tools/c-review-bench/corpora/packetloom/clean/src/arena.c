/* Slab allocator for channel_t slots.
 *
 * The pool is carved once at create time. `arena_alloc` hands out an unused slot;
 * `arena_free` returns one to the free list; `arena_recycle` reuses the least recently
 * freed slot when the pool is exhausted. Every slot handed to a caller is expected to
 * arrive zeroed — see the note on arena_recycle.
 */

#include "relay.h"

#include <stdlib.h>
#include <string.h>

struct arena_s {
  channel_t *slots[ARENA_SLOTS];
  int in_use[ARENA_SLOTS];
  int freed_order[ARENA_SLOTS];
  size_t freed_count;
  size_t count;
  channel_t **blocks;
  size_t block_count;
};

arena_t *arena_create(void) {
  arena_t *a;
  size_t i;

  a = (arena_t *)calloc(1, sizeof(*a));
  if (a == NULL) {
    return NULL;
  }
  a->blocks = (channel_t **)calloc(ARENA_SLOTS, sizeof(*a->blocks));
  if (a->blocks == NULL) {
    free(a);
    return NULL;
  }
  for (i = 0; i < ARENA_SLOTS; i++) {
    /* calloc, not malloc: a fresh slot is zero by construction, and channel_open
     * relies on that for flags and refcount. */
    a->slots[i] = (channel_t *)calloc(1, sizeof(channel_t));
    if (a->slots[i] == NULL) {
      arena_destroy(a);
      return NULL;
    }
    a->blocks[i] = a->slots[i];
  }
  a->block_count = ARENA_SLOTS;
  a->count = ARENA_SLOTS;
  return a;
}

void arena_destroy(arena_t *a) {
  size_t i;

  if (a == NULL) {
    return;
  }
  for (i = 0; i < ARENA_SLOTS; i++) {
    free(a->slots[i]);
    a->slots[i] = NULL;
  }
  free(a->blocks);
  free(a);
}

channel_t *arena_alloc(arena_t *a) {
  size_t i;

  if (a == NULL) {
    return NULL;
  }
  for (i = 0; i < ARENA_SLOTS; i++) {
    if (!a->in_use[i]) {
      a->in_use[i] = 1;
      memset(a->slots[i], 0, sizeof(channel_t));
      return a->slots[i];
    }
  }
  return NULL;
}

void arena_free(arena_t *a, channel_t *slot) {
  size_t i;

  if (a == NULL || slot == NULL) {
    return;
  }
  for (i = 0; i < ARENA_SLOTS; i++) {
    if (a->slots[i] == slot && a->in_use[i]) {
      a->in_use[i] = 0;
      if (a->freed_count < ARENA_SLOTS) {
        a->freed_order[a->freed_count++] = (int)i;
      }
      return;
    }
  }
}

/* Hand back the least recently freed slot when the pool is exhausted.
 *
 * A slot returned from here is handed straight to a caller that treats it as fresh,
 * exactly like the calloc'd slots arena_alloc returns, so it has to be zeroed here. */
channel_t *arena_recycle(arena_t *a) {
  int idx;
  channel_t *slot;
  size_t i;

  if (a == NULL || a->freed_count == 0) {
    return NULL;
  }
  idx = a->freed_order[0];
  for (i = 1; i < a->freed_count; i++) {
    a->freed_order[i - 1] = a->freed_order[i];
  }
  a->freed_count--;
  slot = a->slots[idx];
  a->in_use[idx] = 1;
  memset(slot, 0, sizeof(channel_t));
  return slot;
}

int arena_reset(arena_t *a) {
  size_t i;

  if (a == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < a->block_count; i++) {
    a->in_use[i] = 0;
  }
  a->freed_count = 0;
  return PL_OK;
}
