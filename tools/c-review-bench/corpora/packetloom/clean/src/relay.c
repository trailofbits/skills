/* Entry points, control dispatch and retry scheduling.
 *
 * relay_on_frame  — REMOTE. Every byte comes from a peer.
 * relay_on_control — LOCAL_UNPRIVILEGED. A local IPC control channel.
 *
 * The control dispatch table pairs each opcode with the minimum body length its
 * handler needs. A handler is entered only once that many bytes are present, so each
 * handler may read up to its own declared minimum without further checks.
 */

#include "relay.h"

#include <string.h>

typedef int (*ctrl_fn)(session_t *s, const uint8_t *body, size_t len);

static int ctrl_open(session_t *s, const uint8_t *body, size_t len);
static int ctrl_close(session_t *s, const uint8_t *body, size_t len);
static int ctrl_label(session_t *s, const uint8_t *body, size_t len);
static int ctrl_decode(session_t *s, const uint8_t *body, size_t len);
static int ctrl_peer(session_t *s, const uint8_t *body, size_t len);

struct ctrl_entry {
  uint8_t op;
  size_t min_len;
  ctrl_fn fn;
};

/* Each min_len is the number of body bytes its handler reads unconditionally:
 * chan id (2) + one selector byte = 3, for every entry. */
static const struct ctrl_entry g_dispatch[] = {
    {OP_OPEN_CHANNEL, 3, ctrl_open},
    {OP_CLOSE_CHANNEL, 3, ctrl_close},
    {OP_SET_LABEL, 3, ctrl_label},
    {OP_DECODE_FIELD, 3, ctrl_decode},
    {OP_SET_PEER, 3, ctrl_peer},
};

static int ctrl_open(session_t *s, const uint8_t *body, size_t len) {
  return control_msg_open(s, body, len);
}

static int ctrl_close(session_t *s, const uint8_t *body, size_t len) {
  uint16_t chan_id;
  uint8_t selector;

  (void)len;
  chan_id = rd_be16(body);
  selector = body[2];
  if (selector != 0) {
    return PL_ERR_FORMAT;
  }
  return channel_close(s, chan_id);
}

static int ctrl_label(session_t *s, const uint8_t *body, size_t len) {
  uint16_t chan_id;
  uint8_t label_len;
  channel_t *chan;
  uint8_t staged[LABEL_MAX];
  char text[LABEL_MAX];

  chan_id = rd_be16(body);
  label_len = body[2];
  if (len < (size_t)3 + label_len) {
    return PL_ERR_SHORT;
  }
  chan = channel_find(s, chan_id);
  if (chan == NULL) {
    return PL_ERR_NO_CHANNEL;
  }
  if (label_len >= sizeof(staged)) {
    return PL_ERR_LABEL_TOO_LONG;
  }
  copy_field(staged, sizeof(staged), body + 3, label_len);
  memset(text, 0, sizeof(text));
  memcpy(text, staged, label_len);
  return channel_set_label(chan, text);
}

static int ctrl_decode(session_t *s, const uint8_t *body, size_t len) {
  return control_msg_decode(s, body, len);
}

static int ctrl_peer(session_t *s, const uint8_t *body, size_t len) {
  uint8_t name_len;

  name_len = body[2];
  if (len < (size_t)3 + name_len) {
    return PL_ERR_SHORT;
  }
  return session_set_peer_name(s, (const char *)(body + 3), name_len);
}

int control_msg_open(session_t *s, const uint8_t *body, size_t len) {
  uint8_t label_len;
  uint8_t staged[LABEL_MAX];
  channel_t *chan = NULL;

  if (s == NULL || body == NULL || len < 3) {
    return PL_ERR_SHORT;
  }
  label_len = body[2];
  if (len < (size_t)3 + label_len) {
    return PL_ERR_SHORT;
  }
  if (label_len >= sizeof(staged)) {
    return PL_ERR_LABEL_TOO_LONG;
  }
  copy_field(staged, sizeof(staged), body + 3, label_len);
  return channel_open(s, (const char *)staged, label_len, &chan);
}

/* Decode a generic control field into the session scratch buffer. */
int control_msg_decode(session_t *s, const uint8_t *body, size_t len) {
  size_t field_len;

  if (s == NULL || body == NULL || len < 2) {
    return PL_ERR_SHORT;
  }
  field_len = rd_be16(body);
  if (field_len > len - 2) {
    return PL_ERR_SHORT;
  }
  if (field_len > sizeof(s->scratch)) {
    return PL_ERR_LIMIT;
  }
  copy_field(s->scratch, sizeof(s->scratch), body + 2, field_len);
  return PL_OK;
}

int relay_route_control(session_t *s, uint8_t op, const uint8_t *body, size_t len) {
  size_t i;

  if (s == NULL || body == NULL) {
    return PL_ERR;
  }
  for (i = 0; i < sizeof(g_dispatch) / sizeof(g_dispatch[0]); i++) {
    if (g_dispatch[i].op != op) {
      continue;
    }
    if (len < g_dispatch[i].min_len) {
      return PL_ERR_SHORT;
    }
    return g_dispatch[i].fn(s, body, len);
  }
  if (op == OP_CLOSE_SESSION) {
    return relay_close_session(s);
  }
  return PL_ERR_FORMAT;
}

int relay_on_control(session_t *s, const uint8_t *buf, size_t len) {
  if (s == NULL || buf == NULL || len < 1) {
    return PL_ERR_SHORT;
  }
  if (!s->active) {
    return PL_ERR_STATE;
  }
  return relay_route_control(s, buf[0], buf + 1, len - 1);
}

int frame_dispatch_payload(session_t *s, uint8_t codec_id, const uint8_t *p, size_t len) {
  const codec_t *codec;
  uint8_t out[SCRATCH_MAX];
  size_t out_len = 0;
  int rc;

  if (s == NULL || p == NULL) {
    return PL_ERR;
  }
  codec = codec_lookup(codec_id);
  if (codec == NULL || codec->decode == NULL) {
    return PL_ERR_FORMAT;
  }
  rc = codec->decode(&s->codec_ctx, p, len, out, &out_len);
  if (rc != PL_OK) {
    return rc;
  }
  if (out_len > sizeof(s->scratch)) {
    return PL_ERR_LIMIT;
  }
  copy_field(s->scratch, sizeof(s->scratch), out, out_len);
  return PL_OK;
}

int relay_schedule_retry(session_t *s, uint16_t chan_id) {
  channel_t *chan;
  unsigned i;

  if (s == NULL) {
    return PL_ERR;
  }
  chan = channel_find(s, chan_id);
  if (chan == NULL) {
    return PL_ERR_NO_CHANNEL;
  }
  for (i = 0; i < MAX_RETRIES; i++) {
    if (s->retry_depth >= 2) {
      break;
    }
    s->retry_depth++;
  }
  return PL_OK;
}

int relay_close_session(session_t *s) {
  if (s == NULL) {
    return PL_ERR;
  }
  if (!s->active) {
    return PL_ERR_STATE;
  }
  return session_destroy(s);
}

int relay_on_frame(session_t *s, const uint8_t *buf, size_t len) {
  frame_hdr_t hdr;
  frag_hdr_t fh;
  const uint8_t *body;
  size_t body_len;
  char name[NAME_MAX_LEN];
  uint32_t w0 = 0, w1 = 0, w2 = 0;
  channel_t *chan;
  int rc;

  if (s == NULL || buf == NULL) {
    return PL_ERR;
  }
  if (!s->active) {
    return PL_ERR_STATE;
  }

  rc = frame_parse_header(buf, len, &hdr);
  if (rc != PL_OK) {
    return rc;
  }
  if (hdr.payload_len < FRAG_HDR_LEN) {
    return PL_ERR_SHORT;
  }

  rc = reasm_on_fragment_header(s, hdr.payload, hdr.payload_len, &fh);
  if (rc != PL_OK) {
    return rc;
  }

  body = hdr.payload + FRAG_HDR_LEN;
  body_len = hdr.payload_len - FRAG_HDR_LEN;

  /* An index block, when the fragment carries one. */
  if ((fh.priority & 0x80) != 0) {
    rc = reasm_scan_index(body, body_len, &w0, &w1, &w2);
    if (rc != PL_OK) {
      return rc;
    }
  }

  /* An optional name field, when the fragment carries one. */
  if ((fh.priority & 0x40) != 0) {
    rc = frame_parse_name(body, body_len, name, sizeof(name));
    if (rc != PL_OK) {
      return rc;
    }
  }

  rc = reasm_absorb(s, &fh, body, body_len);
  if (rc != PL_OK) {
    return rc;
  }

  /* Priority frames take the fast path into the channel's retry bookkeeping. */
  if ((fh.priority & 0x20) != 0) {
    chan = channel_find(s, fh.chan);
    if (chan != NULL) {
      rc = channel_inject_control(s, chan, fh.index);
      if (rc != PL_OK) {
        return rc;
      }
    }
  }

  /* Ordinary acks close out a retry slot. */
  if ((fh.priority & 0x10) != 0) {
    chan = channel_find(s, fh.chan);
    if (chan != NULL) {
      rc = channel_on_ack(s, chan, fh.index);
      if (rc != PL_OK) {
        return rc;
      }
      rc = channel_send(s, chan, fh.index);
      if (rc != PL_OK) {
        return rc;
      }
    }
  }

  /* Windowed transfers report their remaining credit. */
  if ((fh.priority & 0x08) != 0 && body_len >= 8) {
    if (session_window_credit(s, fh.chan, rd_be32(body), rd_be32(body + 4)) < 0) {
      return PL_ERR_LIMIT;
    }
  }

  rc = frame_dispatch_payload(s, hdr.priority & 0x07, body, body_len);
  if (rc != PL_OK) {
    return rc;
  }

  /* Last: the hook is documented as allowed to call relay_close_session(s), which frees
   * rx_buf, so nothing may touch the session after this returns. */
  if (s->on_frame != NULL) {
    s->on_frame(s, s->rx_buf, s->rx_len);
  }
  return PL_OK;
}
