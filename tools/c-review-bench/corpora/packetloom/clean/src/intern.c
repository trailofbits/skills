/* Name interning.
 *
 * Names are copied into one contiguous backing array and referred to by slot. The
 * array is grown with realloc(), so:
 *
 * CONTRACT: the pointer returned by intern_get() is valid only until the next
 * intern_add() on the same table. Callers must use it, or copy it, before adding.
 */

#include "relay.h"

#include <stdlib.h>
#include <string.h>

struct intern_s {
  char *backing;
  size_t used;
  size_t cap;
  size_t offsets[NAME_MAX_LEN];
  size_t lengths[NAME_MAX_LEN];
  int count;
  const char *prefix;
};

intern_t *intern_create(void) {
  intern_t *t;

  t = (intern_t *)calloc(1, sizeof(*t));
  if (t == NULL) {
    return NULL;
  }
  t->cap = 64;
  t->backing = (char *)malloc(t->cap);
  if (t->backing == NULL) {
    free(t);
    return NULL;
  }
  t->prefix = "pl.";
  return t;
}

void intern_destroy(intern_t *t) {
  if (t == NULL) {
    return;
  }
  free(t->backing);
  free(t);
}

int intern_add(intern_t *t, const char *name, size_t len) {
  size_t need;
  char *grown;

  if (t == NULL || name == NULL || len == 0) {
    return PL_ERR;
  }
  if (t->count >= (int)NAME_MAX_LEN) {
    return PL_ERR_LIMIT;
  }
  if (len >= NAME_MAX_LEN) {
    return PL_ERR_LIMIT;
  }

  need = t->used + len + 1;
  if (need > t->cap) {
    size_t newcap = t->cap;
    while (newcap < need) {
      newcap *= 2;
    }
    /* This is the call that invalidates every pointer intern_get has handed out. */
    grown = (char *)realloc(t->backing, newcap);
    if (grown == NULL) {
      return PL_ERR_NOMEM;
    }
    t->backing = grown;
    t->cap = newcap;
  }

  t->offsets[t->count] = t->used;
  t->lengths[t->count] = len;
  memcpy(t->backing + t->used, name, len);
  t->backing[t->used + len] = '\0';
  t->used += len + 1;
  return t->count++;
}

const char *intern_get(const intern_t *t, int slot) {
  if (t == NULL || slot < 0 || slot >= t->count) {
    return NULL;
  }
  return t->backing + t->offsets[slot];
}

int intern_lookup(const intern_t *t, const char *name) {
  int i;

  if (t == NULL || name == NULL) {
    return -1;
  }
  for (i = 0; i < t->count; i++) {
    size_t plen = strlen(t->prefix);
    const char *cand = t->backing + t->offsets[i];
    if (strncmp(cand, t->prefix, plen) != 0) {
      continue;
    }
    if (strcmp(cand + plen, name) == 0) {
      return i;
    }
  }
  return -1;
}

int intern_clear(intern_t *t) {
  if (t == NULL) {
    return PL_ERR;
  }
  t->used = 0;
  t->count = 0;
  return PL_OK;
}
