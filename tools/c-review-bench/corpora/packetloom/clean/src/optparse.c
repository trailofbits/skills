/* Config/option parser.
 *
 * Grammar: entries := (field | group) (';' (field | group))*
 *          field   := key '=' value
 *          group   := name '{' entries '}'
 *
 * A group's body is itself an entry list, so parsing one is a recursive call, and
 * "chan<id>{...}" changes which channel subsequent fields inside the group apply to.
 * The only bound on nesting depth is the explicit `depth` counter threaded through
 * every recursive call: a control message a few hundred bytes long can still encode
 * hundreds of nested empty groups ("{{{{...}}}}"), so the depth check is what stands
 * between that and unbounded stack growth.
 */

#include "relay.h"

#include <stdlib.h>
#include <string.h>

static unsigned parse_uint(const char *p, size_t len) {
  unsigned v = 0;
  size_t i;

  for (i = 0; i < len && i < 9; i++) {
    if (p[i] < '0' || p[i] > '9') {
      break;
    }
    v = v * 10 + (unsigned)(p[i] - '0');
  }
  return v;
}

static int opt_apply_field(session_t *s, channel_t *chan, const char *text, size_t len) {
  size_t eq = len;
  size_t i;
  const char *key;
  size_t key_len;
  const char *value;
  size_t value_len;

  for (i = 0; i < len; i++) {
    if (text[i] == '=') {
      eq = i;
      break;
    }
  }
  if (eq == len) {
    return PL_OK; /* a bare flag with no value; nothing to apply */
  }
  key = text;
  key_len = eq;
  value = text + eq + 1;
  value_len = len - eq - 1;

  if (key_len == 7 && strncmp(key, "verbose", 7) == 0) {
    log_set_sink(parse_uint(value, value_len) != 0);
    return PL_OK;
  }
  if (key_len == 4 && strncmp(key, "peer", 4) == 0) {
    if (value_len >= NAME_MAX_LEN) {
      return PL_ERR_LIMIT;
    }
    return session_set_peer_name(s, value, value_len);
  }
  if (key_len == 5 && strncmp(key, "label", 5) == 0) {
    uint8_t staged[LABEL_MAX];
    char text_buf[LABEL_MAX];

    if (chan == NULL) {
      return PL_ERR_NO_CHANNEL;
    }
    if (value_len >= LABEL_MAX) {
      return PL_ERR_LABEL_TOO_LONG;
    }
    copy_field(staged, sizeof(staged), (const uint8_t *)value, value_len);
    memset(text_buf, 0, sizeof(text_buf));
    memcpy(text_buf, staged, value_len);
    return channel_set_label(chan, text_buf);
  }
  if (key_len == 8 && strncmp(key, "priority", 8) == 0) {
    if (chan == NULL) {
      return PL_ERR_NO_CHANNEL;
    }
    if (parse_uint(value, value_len) != 0) {
      chan->flags |= CH_FLAG_PRIORITY;
    } else {
      chan->flags &= (uint8_t)~CH_FLAG_PRIORITY;
    }
    return PL_OK;
  }
  if (key_len == 4 && strncmp(key, "note", 4) == 0) {
    /* A short free-form annotation, logged rather than stored. */
    char note_buf[NAME_MAX_LEN];

    if (value_len >= sizeof(note_buf)) {
      return PL_ERR_LIMIT;
    }
    memset(note_buf, 0, sizeof(note_buf));
    memcpy(note_buf, value, value_len);
    log_write("note %s", note_buf);
    return PL_OK;
  }
  if (key_len == 3 && strncmp(key, "tag", 3) == 0) {
    char tag_buf[8];

    if (value_len >= sizeof(tag_buf)) {
      return PL_ERR_LIMIT;
    }
    memcpy(tag_buf, value, value_len);
    tag_buf[value_len] = '\0';
    log_write("tag %s", tag_buf);
    return PL_OK;
  }
  return PL_ERR_FORMAT;
}

static int opt_parse(session_t *s, channel_t *chan, const char *text, size_t len, unsigned depth) {
  size_t i = 0;

  if (s == NULL) {
    return PL_ERR;
  }
  if (depth > OPT_MAX_DEPTH) {
    return PL_ERR_LIMIT;
  }
  while (i < len) {
    size_t start = i;
    size_t brace_depth = 0;
    size_t brace_open = (size_t)-1;
    size_t entry_end;

    while (i < len) {
      char ch = text[i];
      if (ch == '{') {
        if (brace_depth == 0) {
          brace_open = i;
        }
        brace_depth++;
      } else if (ch == '}') {
        if (brace_depth > 0) {
          brace_depth--;
        }
      } else if (ch == ';' && brace_depth == 0) {
        break;
      }
      i++;
    }
    entry_end = i;

    if (brace_open != (size_t)-1) {
      size_t name_len = brace_open - start;
      size_t body_start = brace_open + 1;
      size_t body_end = entry_end;
      channel_t *target = chan;
      int rc;

      if (body_end > body_start && text[body_end - 1] == '}') {
        body_end--;
      }
      if (name_len > 10 && strncmp(text + start, "chanlabel:", 10) == 0) {
        target = channel_find_by_label(s, text + start + 10, name_len - 10);
      } else if (name_len >= 4 && strncmp(text + start, "chan", 4) == 0) {
        target = channel_find(s, (uint16_t)parse_uint(text + start + 4, name_len - 4));
      }
      /* Every recursive descent into a nested group must count against
       * OPT_MAX_DEPTH, or a control message built entirely of empty nested
       * groups recurses without bound. */
      rc = opt_parse(s, target, text + body_start, body_end - body_start, depth + 1);
      if (rc != PL_OK) {
        return rc;
      }
    } else if (entry_end > start) {
      int rc = opt_apply_field(s, chan, text + start, entry_end - start);
      if (rc != PL_OK) {
        return rc;
      }
    }
    i = entry_end + 1;
  }
  return PL_OK;
}

int opt_apply(session_t *s, const char *text, size_t len) {
  if (s == NULL || text == NULL) {
    return PL_ERR;
  }
  return opt_parse(s, NULL, text, len, 0);
}

/* A batch of option strings applied in one control message: count(1) then, count
 * times, a (len(2) text[len]) entry. Every entry's length is checked against what
 * actually remains in the buffer before opt_apply() reads it. */
int opt_apply_bulk(session_t *s, const uint8_t *buf, size_t avail) {
  uint8_t count;
  size_t cursor;
  uint8_t i;

  if (s == NULL || buf == NULL || avail < 1) {
    return PL_ERR_SHORT;
  }
  count = buf[0];
  cursor = 1;
  for (i = 0; i < count; i++) {
    size_t text_len;
    int rc;

    if (cursor + 2 > avail) {
      return PL_ERR_SHORT;
    }
    text_len = rd_be16(buf + cursor);
    cursor += 2;
    if (text_len > avail - cursor) {
      return PL_ERR_SHORT;
    }
    rc = opt_apply(s, (const char *)(buf + cursor), text_len);
    if (rc != PL_OK) {
      return rc;
    }
    cursor += text_len;
  }
  return PL_OK;
}
