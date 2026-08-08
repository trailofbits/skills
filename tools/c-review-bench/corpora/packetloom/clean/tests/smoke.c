/* Benign-input behaviour check.
 *
 * Every value here stays well inside every documented limit, because the point is to
 * prove the corpus still behaves identically after injection — not to reach any bug.
 * In particular: labels stay under LABEL_MAX, names under 32 bytes, channel ids under
 * 64, pending_acks well under MAX_WINDOW, and no callback closes its own session.
 */

#include "relay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *what) {
  if (!cond) {
    printf("FAIL %s\n", what);
    failures++;
  }
}

static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void put_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static size_t build_frame(uint8_t *buf, uint8_t priority, const uint8_t *body, size_t body_len) {
  buf[0] = PL_MAGIC0;
  buf[1] = PL_MAGIC1;
  buf[2] = PL_VERSION;
  buf[3] = priority;
  put_be32(buf + 4, (uint32_t)body_len);
  memcpy(buf + HEADER_LEN, body, body_len);
  return HEADER_LEN + body_len;
}

static void test_header(void) {
  uint8_t body[32];
  uint8_t buf[128];
  frame_hdr_t hdr;
  size_t n;

  memset(body, 0, sizeof(body));
  n = build_frame(buf, 0, body, 16);
  check(frame_parse_header(buf, n, &hdr) == PL_OK, "header parses");
  check(hdr.total_len == 16, "total_len round-trips");
  check(hdr.version == PL_VERSION, "version round-trips");

  buf[0] = 0x00;
  check(frame_parse_header(buf, n, &hdr) == PL_ERR_FORMAT, "bad magic rejected");
  buf[0] = PL_MAGIC0;
  check(frame_parse_header(buf, 4, &hdr) == PL_ERR_SHORT, "short header rejected");
}

static void test_name(void) {
  uint8_t p[64];
  char out[64];

  memset(p, 0, sizeof(p));
  put_be16(p, 5);
  memcpy(p + 2, "alpha", 5);
  check(frame_parse_name(p, 7, out, sizeof(out)) == PL_OK, "name parses");
  check(strcmp(out, "alpha") == 0, "name round-trips");
}

static void test_codecs(void) {
  codec_ctx_t ctx;
  uint8_t src[64];
  uint8_t out[SCRATCH_MAX];
  size_t out_len = 0;
  const codec_t *c;

  memset(&ctx, 0, sizeof(ctx));
  memset(src, 0, sizeof(src));
  put_be16(src, 8);
  memcpy(src + 2, "abcdefgh", 8);

  codec_init_all();
  c = codec_lookup(CODEC_RAW);
  check(c != NULL, "raw codec registered");
  check(codec_raw_decode(&ctx, src, 10, out, &out_len) == PL_OK, "raw decodes");
  check(out_len == 8, "raw length");

  check(codec_dict_decode(&ctx, src, 10, out, &out_len) == PL_OK, "dict decodes");
  check(out_len == 8, "dict length");

  check(codec_chunked_decode(&ctx, src, 10, out, &out_len) == PL_OK, "chunked decodes");
  check(out_len == 8, "chunked length");

  check(codec_delta_decode(&ctx, src, 10, out, &out_len) == PL_OK, "delta decodes");
  check(codec_rle_decode(&ctx, src, 10, out, &out_len) == PL_OK, "rle decodes");

  /* varint takes a 32-bit unit count: 2 units -> 8 bytes, well under dst[64]. */
  memset(src, 0, sizeof(src));
  put_be32(src, 2);
  memcpy(src + 4, "abcdefgh", 8);
  check(codec_varint_decode(&ctx, src, 12, out, &out_len) == PL_OK, "varint decodes");
  check(out_len == 8, "varint length");
}

static void test_pack_id(void) {
  /* Ids stay under 64 here; the packing is exercised, not its range. */
  check(channel_unpack_id(channel_pack_id(7, 1)) == 7, "id 7 round-trips");
  check(channel_unpack_id(channel_pack_id(31, 0)) == 31, "id 31 round-trips");
}

static void test_index_scan(void) {
  uint8_t buf[32];
  uint32_t a = 0, b = 0, c = 0;

  memset(buf, 0, sizeof(buf));
  put_be32(buf + 0, 1);
  put_be32(buf + 4, 2);
  put_be32(buf + 8, 3);
  check(reasm_scan_index(buf, 12, &a, &b, &c) == PL_OK, "index scan");
  check(a == 1 && b == 2 && c == 3, "index words round-trip");
  check(reasm_scan_index(buf, 6, &a, &b, &c) == PL_ERR_SHORT, "short index rejected");
}

static void test_session_and_channels(void) {
  session_t *s;
  channel_t *chan = NULL;
  uint8_t ctrl[32];
  int rc;
  int slot;

  s = session_create(0);
  check(s != NULL, "session created");
  if (s == NULL) {
    return;
  }

  rc = channel_open(s, "log", 3, &chan);
  check(rc == PL_OK, "channel opens");
  check(chan != NULL, "channel returned");
  if (chan != NULL) {
    check(chan->flags == CH_FLAG_OPEN, "fresh channel flags");
    check(chan->refcount == 1, "fresh channel refcount");
    check(chan->pending_acks == 0, "fresh channel acks");
    check(channel_set_label(chan, "logs") == PL_OK, "label set");
    check(channel_send(s, chan, 1) == PL_OK, "send accounts one ack");
    check(chan->pending_acks == 1, "one pending ack");
    check(channel_on_ack(s, chan, 1) == PL_OK, "ack clears");
    check(chan->pending_acks == 0, "no pending acks");
    check(channel_inject_control(s, chan, 2) == PL_OK, "priority inject");
    check(chan->pending_acks == 1, "inject accounts one ack");
    check(channel_on_ack(s, chan, 2) == PL_OK, "inject ack clears");
  }

  /* An over-long label is rejected and must not consume an arena slot. */
  chan = NULL;
  rc = channel_open(s, "0123456789abcdefghij", 20, &chan);
  check(rc == PL_ERR_LABEL_TOO_LONG, "long label rejected");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_SET_LABEL;
  put_be16(ctrl + 1, 0);
  ctrl[3] = 3;
  memcpy(ctrl + 4, "abc", 3);
  check(relay_on_control(s, ctrl, 7) == PL_OK, "control set-label routes");

  check(session_set_peer_name(s, "peer-one", 8) == PL_OK, "peer name set");
  check(strcmp(s->peer_name, "peer-one") == 0, "peer name round-trips");

  check(session_window_credit(s, 0, 16, 16) >= 0, "window credit");

  /* channel_open interns the channel label, so slot numbers are relative. */
  slot = intern_add(s->intern, "pl.alpha", 8);
  check(slot >= 0, "intern add");
  check(intern_get(s->intern, slot) != NULL, "intern get");
  check(intern_lookup(s->intern, "alpha") == slot, "intern lookup");
  check(log_field(s, slot, "beta") == PL_OK, "log field");

  check(relay_schedule_retry(s, 0) == PL_OK, "retry scheduled");

  check(session_destroy(s) == PL_OK, "session destroyed");
  free(s);
}

static void test_frame_path(void) {
  session_t *s;
  uint8_t body[64];
  uint8_t buf[128];
  size_t n;

  s = session_create(1);
  check(s != NULL, "second session created");
  if (s == NULL) {
    return;
  }

  memset(body, 0, sizeof(body));
  put_be16(body, 0);  /* chan */
  body[2] = 0;        /* index */
  body[3] = 1;        /* count */
  body[4] = CODEC_RAW;
  put_be16(body + FRAG_HDR_LEN, 4);
  memcpy(body + FRAG_HDR_LEN + 2, "wxyz", 4);

  n = build_frame(buf, CODEC_RAW, body, FRAG_HDR_LEN + 6);
  check(relay_on_frame(s, buf, n) == PL_OK, "frame accepted");
  check(s->rx_len == 6, "rx_len tracks absorbed payload");
  check(s->rx_len <= s->rx_cap, "rx_len within capacity");

  check(session_destroy(s) == PL_OK, "second session destroyed");
  free(s);
}

int main(void) {
  log_set_sink(0);

  test_header();
  test_name();
  test_codecs();
  test_pack_id();
  test_index_scan();
  test_session_and_channels();
  test_frame_path();

  if (failures != 0) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("ok\n");
  return 0;
}
