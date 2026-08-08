/* Debug logging.
 *
 * Off by default so the benign smoke run stays quiet; the sink is enabled only by the
 * embedding application. The interesting part of this file is that it is the one place
 * that holds an interned name across other table operations — see intern.c's contract.
 */

#include "relay.h"

#include <stdio.h>
#include <string.h>

static int g_sink_enabled = 0;
static unsigned g_lines = 0;

void log_set_sink(int enabled) { g_sink_enabled = enabled ? 1 : 0; }

int log_write(const char *fmt, const char *arg) {
  if (fmt == NULL) {
    return PL_ERR;
  }
  g_lines++;
  if (!g_sink_enabled) {
    return PL_OK;
  }
  fprintf(stderr, fmt, arg != NULL ? arg : "(null)");
  fputc('\n', stderr);
  return PL_OK;
}

int log_flush(void) {
  if (g_sink_enabled) {
    fflush(stderr);
  }
  return PL_OK;
}

/* Emit one "<name> <tag>" line and remember the tag for later lookups.
 *
 * intern_get's result is consumed before intern_add runs, because intern_add may
 * realloc the backing array and invalidate it. */
int log_field(session_t *s, int name_slot, const char *tag) {
  const char *name;
  char held[NAME_MAX_LEN];

  if (s == NULL || s->intern == NULL || tag == NULL) {
    return PL_ERR;
  }
  name = intern_get(s->intern, name_slot);
  if (name == NULL) {
    return PL_ERR_FORMAT;
  }

  /* Copy out before any table mutation: the pointer does not survive intern_add. */
  memset(held, 0, sizeof(held));
  strncpy(held, name, sizeof(held) - 1);

  if (intern_add(s->intern, tag, strlen(tag)) < 0) {
    return PL_ERR;
  }

  log_write("field %s", held);
  return PL_OK;
}
