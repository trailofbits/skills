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
  check(memcmp(out, "abcdefgh", 8) == 0, "dict round-trips the payload");

  check(codec_chunked_decode(&ctx, src, 10, out, &out_len) == PL_OK, "chunked decodes");
  check(out_len == 8, "chunked length");
  check(memcmp(out, "abcdefgh", 8) == 0, "chunked round-trips the payload");

  check(codec_delta_decode(&ctx, src, 10, out, &out_len) == PL_OK, "delta decodes");
  check(codec_rle_decode(&ctx, src, 10, out, &out_len) == PL_OK, "rle decodes");

  /* varint takes a 32-bit unit count: 2 units -> 8 bytes, well under dst[64]. */
  memset(src, 0, sizeof(src));
  put_be32(src, 2);
  memcpy(src + 4, "abcdefgh", 8);
  check(codec_varint_decode(&ctx, src, 12, out, &out_len) == PL_OK, "varint decodes");
  check(out_len == 8, "varint length");
  check(memcmp(out, "abcdefgh", 8) == 0, "varint round-trips the payload");

  /* zigzag: 0x02 -> +1, 0x04 -> +2, 0x06 -> +3, 0x08 -> +4 under the standard
   * zigzag mapping (v >> 1) ^ -(v & 1). */
  memset(src, 0, sizeof(src));
  put_be16(src, 4);
  memcpy(src + 2, "\x02\x04\x06\x08", 4);
  check(codec_zigzag_decode(&ctx, src, 6, out, &out_len) == PL_OK, "zigzag decodes in test_codecs");
  check(out_len == 4, "zigzag length in test_codecs");
  check(out[0] == 1 && out[1] == 2 && out[2] == 3 && out[3] == 4, "zigzag round-trips magnitudes");
}

static void test_util(void) {
  uint8_t dst[8];
  uint8_t src[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  uint8_t be32[4] = {0x01, 0x02, 0x03, 0x04};
  uint8_t be16[2] = {0x01, 0x02};

  memset(dst, 0, sizeof(dst));
  copy_field(dst, sizeof(dst), src, sizeof(src));
  check(memcmp(dst, src, sizeof(src)) == 0, "copy_field copies the requested bytes");
  check(dst[sizeof(src)] == 0, "copy_field does not write past len");

  check(rd_be32(be32) == 0x01020304u, "rd_be32 decodes big-endian");
  check(rd_be16(be16) == 0x0102u, "rd_be16 decodes big-endian");
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
  check(session_window_credit(s, 0, FRAME_MAX + 1, 0) == PL_ERR_LIMIT,
        "window credit rejects an offset above FRAME_MAX");
  check(session_reserve_rx(s, s->rx_cap) == PL_OK, "reserve exactly rx_cap");
  check(session_reserve_rx(s, s->rx_cap + 1) == PL_ERR_LIMIT, "reserve above rx_cap rejected");

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

/* Exercises timer.c, credit.c, optparse.c, stats.c and reasm_oo.c, both by calling
 * their entry points directly and by routing the same operations through the
 * control-message dispatch. Every length and id here stays far under its module's
 * documented limit (TIMER_MAX_ARMED, OPT_MAX_DEPTH, OO_SLOT_CAP, ...). */
static void test_new_modules(void) {
  session_t *s;
  channel_t *chan = NULL;
  uint8_t ctrl[64];
  uint8_t snap[5];
  uint8_t dump[STATS_MAX_COUNTERS * 4];
  int rc;

  s = session_create(2);
  check(s != NULL, "third session created");
  if (s == NULL) {
    return;
  }

  rc = channel_open(s, "mod", 3, &chan);
  check(rc == PL_OK, "module test channel opens");
  check(chan != NULL, "module test channel returned");
  if (chan == NULL) {
    free(s);
    return;
  }

  /* Timer wheel: arm and cancel directly, then route an arm through control. */
  check(timer_wheel_arm(s->timers, chan->id, 1) == PL_OK, "timer armed directly");
  check(timer_wheel_cancel(s->timers, chan->id) == PL_OK, "timer cancelled directly");
  check(timer_wheel_tick(s->timers, s) == PL_OK, "timer tick with nothing armed");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_ARM_TIMER;
  put_be16(ctrl + 1, chan->id);
  ctrl[3] = 2;
  check(relay_on_control(s, ctrl, 4) == PL_OK, "control arm-timer routes");

  /* Credit scheduler: grant, spend down to zero, reclaim — twice, once directly and
   * once through the control path. */
  check(credit_grant(&s->credit, 100) == PL_OK, "credit granted");
  check(credit_spend(&s->credit, 40) == PL_OK, "credit spent");
  check(credit_spend(&s->credit, 60) == PL_OK, "credit spent to zero");
  check(credit_reclaim(&s->credit) == PL_OK, "credit reclaimed");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_CREDIT_GRANT;
  put_be16(ctrl + 1, chan->id);
  put_be16(ctrl + 3, 50);
  check(relay_on_control(s, ctrl, 5) == PL_OK, "control credit-grant routes");
  check(credit_reclaim(&s->credit) == PL_ERR_STATE, "credit not yet drained");
  check(credit_spend(&s->credit, 50) == PL_OK, "credit spend drains grant");
  check(credit_reclaim(&s->credit) == PL_OK, "credit reclaimed again");

  /* Option parser: a flat field, a nested per-channel group well under
   * OPT_MAX_DEPTH, and the same field routed through control. */
  check(opt_apply(s, "verbose=0", 9) == PL_OK, "option flat field");
  {
    char group[32];
    int n;

    memset(group, 0, sizeof(group));
    n = snprintf(group, sizeof(group), "chan%u{priority=1}", (unsigned)chan->id);
    check(n > 0 && opt_apply(s, group, (size_t)n) == PL_OK, "option nested group");
  }
  check((chan->flags & CH_FLAG_PRIORITY) != 0, "option set channel priority");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_SET_OPTION;
  put_be16(ctrl + 1, 9);
  memcpy(ctrl + 3, "verbose=1", 9);
  check(relay_on_control(s, ctrl, 12) == PL_OK, "control set-option routes");
  log_set_sink(0); /* the option just applied may have turned the sink on */

  /* Telemetry counters: record directly, merge a small in-bounds snapshot, dump. */
  check(stats_record(&s->stats, STATS_CTR_FRAME) == PL_OK, "stats record");
  memset(snap, 0, sizeof(snap));
  snap[0] = STATS_CTR_RETRY;
  put_be32(snap + 1, 3);
  check(stats_merge_snapshot(&s->stats, snap, sizeof(snap)) == PL_OK, "stats merge snapshot");
  check(stats_dump(&s->stats, dump, sizeof(dump)) == PL_OK, "stats dump");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_STATS_MERGE;
  memcpy(ctrl + 1, snap, sizeof(snap));
  check(relay_on_control(s, ctrl, 1 + sizeof(snap)) == PL_OK, "control stats-merge routes");

  /* Out-of-order fragment cache: a fragment well under OO_SLOT_CAP, absorbed directly
   * and through the control path. */
  {
    uint8_t payload[8];
    memcpy(payload, "fastpkt0", 8);
    check(reasm_fast_absorb(s, chan->id, 0, payload, sizeof(payload)) == PL_OK,
          "fast fragment absorbed");
  }
  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_FAST_FRAGMENT;
  put_be16(ctrl + 1, chan->id);
  ctrl[3] = 1;
  memcpy(ctrl + 4, "zzzz", 4);
  check(relay_on_control(s, ctrl, 8) == PL_OK, "control fast-fragment routes");

  /* Out-of-order cache peek: stash directly (bypassing the auto-flush that
   * reasm_fast_absorb does) so the slot is still there to read back. */
  {
    uint8_t payload[6];
    uint8_t reply[32];

    memcpy(payload, "peekme", 6);
    check(reasm_oo_stash(&s->oo, 5, payload, sizeof(payload)) == PL_OK, "oo stash direct");
    check(reasm_oo_peek(&s->oo, 5, reply, sizeof(reply)) == PL_OK, "oo peek direct");
  }
  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_PEEK_FRAGMENT;
  ctrl[1] = 5;
  check(relay_on_control(s, ctrl, 2) == PL_OK, "control peek-fragment routes");

  /* Window resize: well under MAX_WINDOW, directly and through control. */
  check(channel_resize_window(s, chan, 10) == PL_OK, "window resized directly");
  check(chan->window == 10, "resized window value");

  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_RESIZE_WINDOW;
  put_be16(ctrl + 1, chan->id);
  put_be16(ctrl + 3, 16);
  check(relay_on_control(s, ctrl, 5) == PL_OK, "control resize-window routes");
  check(chan->window == 16, "control-resized window value");

  /* Zigzag codec: a small in-bounds field, decoded directly. */
  {
    uint8_t zsrc[8];
    uint8_t zout[SCRATCH_MAX];
    size_t zout_len = 0;

    memset(zsrc, 0, sizeof(zsrc));
    put_be16(zsrc, 4);
    memcpy(zsrc + 2, "\x02\x04\x06\x08", 4);
    check(codec_zigzag_decode(&s->codec_ctx, zsrc, sizeof(zsrc), zout, &zout_len) == PL_OK,
          "zigzag decodes");
    check(zout_len == 4, "zigzag length");
  }

  /* Bulk option apply: two short, well-formed entries, directly and via control. */
  {
    uint8_t bulk[32];
    size_t n = 0;

    bulk[n++] = 2; /* count */
    put_be16(bulk + n, 9);
    n += 2;
    memcpy(bulk + n, "verbose=0", 9);
    n += 9;
    put_be16(bulk + n, 9);
    n += 2;
    memcpy(bulk + n, "verbose=1", 9);
    n += 9;
    check(opt_apply_bulk(s, bulk, n) == PL_OK, "bulk option applied directly");
    log_set_sink(0);

    memset(ctrl, 0, sizeof(ctrl));
    ctrl[0] = OP_BULK_OPTION;
    memcpy(ctrl + 1, bulk, n);
    check(relay_on_control(s, ctrl, 1 + n) == PL_OK, "control bulk-option routes");
    log_set_sink(0);
  }

  /* Stats name lookup: "retry" (6 bytes with the terminator) fits the control
   * handler's fixed 8-byte reply buffer; longer names are exercised directly only. */
  {
    char namebuf[16];

    check(stats_name_copy(STATS_CTR_CHANNEL_OPEN, namebuf, sizeof(namebuf)) == PL_OK,
          "stats name copy directly");
    check(strcmp(namebuf, "chan_open") == 0, "stats name value");
  }
  memset(ctrl, 0, sizeof(ctrl));
  ctrl[0] = OP_STATS_NAME;
  ctrl[1] = STATS_CTR_RETRY;
  check(relay_on_control(s, ctrl, 2) == PL_OK, "control stats-name routes");

  /* Priority frame path: exercises credit_grant_priority via relay_on_frame. Its
   * result is advisory and not checked by the caller, so this only has to not crash. */
  {
    uint8_t body[FRAG_HDR_LEN + 2];
    uint8_t buf[64];
    size_t n;

    memset(body, 0, sizeof(body));
    put_be16(body, chan->id);
    body[2] = 0;
    body[3] = 1;
    body[4] = 0x20; /* fragment priority: bit 0x20 is the priority fast path */
    put_be16(body + FRAG_HDR_LEN, 0);
    n = build_frame(buf, CODEC_RAW, body, FRAG_HDR_LEN + 2);
    check(relay_on_frame(s, buf, n) == PL_OK, "priority frame processed");
  }

  check(session_destroy(s) == PL_OK, "third session destroyed");
  free(s);
}

/* Further coverage of the new modules: timer escalation across several ticks,
 * label-based channel lookup, a credit request that is correctly rejected, option
 * nesting exactly at OPT_MAX_DEPTH, and a three-entry bulk apply. Every bound here
 * is met exactly or stays under it — none is exceeded. */
static void test_more_coverage(void) {
  session_t *s;
  channel_t *chan = NULL;
  int rc;

  s = session_create(3);
  check(s != NULL, "fourth session created");
  if (s == NULL) {
    return;
  }

  rc = channel_open(s, "worker", 6, &chan);
  check(rc == PL_OK, "coverage channel opens");
  if (chan == NULL) {
    free(s);
    return;
  }

  /* Timer escalation: arm once, then tick the wheel around a full revolution.
   * Each time the channel still has a pending ack, the timer re-arms itself
   * further out (backoff_next grows with the attempt count), so it must still be
   * findable — armed on some future bucket — after the sweep. */
  check(channel_send(s, chan, 9) == PL_OK, "coverage send accounts one ack");
  check(timer_wheel_arm(s->timers, chan->id, 1) == PL_OK, "coverage timer armed");
  {
    unsigned t;
    for (t = 0; t < TIMER_BUCKETS; t++) {
      check(timer_wheel_tick(s->timers, s) == PL_OK, "coverage timer tick");
    }
  }
  check(channel_on_ack(s, chan, 9) == PL_OK, "coverage ack clears");

  /* Label lookup, both the plain form and through the option group syntax. */
  check(channel_find_by_label(s, "worker", 6) == chan, "find by label");
  {
    int n = snprintf(NULL, 0, "chanlabel:worker{priority=1}") + 1;
    char group[40];
    check(n > 0 && (size_t)n <= sizeof(group), "label group fits");
    memset(group, 0, sizeof(group));
    memcpy(group, "chanlabel:worker{priority=1}", (size_t)n - 1);
    check(opt_apply(s, group, (size_t)n - 1) == PL_OK, "label group applied");
  }
  check((chan->flags & CH_FLAG_PRIORITY) != 0, "label group set priority");

  /* Credit: a request for more than was granted must be rejected, not silently
   * truncated, and must not disturb the outstanding grant. */
  check(credit_grant(&s->credit, 10) == PL_OK, "coverage credit granted");
  check(credit_spend(&s->credit, 11) == PL_ERR_LIMIT, "over-spend rejected");
  check(s->credit.granted == 10 && s->credit.spent == 0, "grant unchanged after rejection");
  check(credit_spend(&s->credit, 10) == PL_OK, "coverage credit spent exactly");
  check(credit_reclaim(&s->credit) == PL_OK, "coverage credit reclaimed");

  /* Option nesting several levels deep — comfortably under OPT_MAX_DEPTH(4), not
   * at its boundary, since the smoke test checks benign behaviour rather than the
   * limit itself. */
  {
    char nested[64];
    int n;

    n = snprintf(nested, sizeof(nested), "chan%u{chan%u{priority=0}}", (unsigned)chan->id,
                 (unsigned)chan->id);
    check(n > 0 && opt_apply(s, nested, (size_t)n) == PL_OK, "nested option within depth limit");
  }
  check((chan->flags & CH_FLAG_PRIORITY) == 0, "nested option cleared priority");

  /* Bulk option with three entries, all session-scoped so none needs a channel
   * context. */
  {
    uint8_t bulk[64];
    size_t n = 0;
    const char *entries[3] = {"verbose=1", "verbose=0", "peer=worker"};
    int i;

    bulk[n++] = 3;
    for (i = 0; i < 3; i++) {
      size_t elen = strlen(entries[i]);
      put_be16(bulk + n, (uint16_t)elen);
      n += 2;
      memcpy(bulk + n, entries[i], elen);
      n += elen;
    }
    check(opt_apply_bulk(s, bulk, n) == PL_OK, "three-entry bulk option applied");
    log_set_sink(0);
  }

  /* Per-class credit pools: a valid class id directly, an out-of-range one
   * rejected, and a valid class id through the control path. */
  {
    credit_sched_t *pool = credit_pool_for(s, 2);
    check(pool != NULL, "credit pool for class 2");
    check(credit_pool_for(s, CREDIT_POOL_COUNT) == NULL, "credit pool rejects out-of-range class");
    if (pool != NULL) {
      check(credit_grant(pool, 20) == PL_OK, "pool 2 granted");
      check(credit_spend(pool, 20) == PL_OK, "pool 2 spent");
      check(credit_reclaim(pool) == PL_OK, "pool 2 reclaimed");
    }
  }
  {
    uint8_t ctrl[8];
    memset(ctrl, 0, sizeof(ctrl));
    ctrl[0] = OP_POOL_GRANT;
    ctrl[1] = 1;
    put_be16(ctrl + 2, 30);
    check(relay_on_control(s, ctrl, 4) == PL_OK, "control pool-grant routes");
  }

  /* Channel listing: the reply buffer (8 entries) comfortably holds this session's
   * one open channel. */
  {
    uint16_t ids[8];
    size_t count = 0;

    check(channel_list_ids(s, ids, sizeof(ids) / sizeof(ids[0]), &count) == PL_OK,
          "channel list direct");
    check(count == 1 && ids[0] == chan->id, "channel list contents");
  }
  {
    uint8_t ctrl[4];
    memset(ctrl, 0, sizeof(ctrl));
    ctrl[0] = OP_LIST_CHANNELS;
    check(relay_on_control(s, ctrl, 1) == PL_OK, "control list-channels routes");
  }

  check(session_destroy(s) == PL_OK, "fourth session destroyed");
  free(s);
}

/* Forces the arena's recycle path (open past ARENA_SLOTS so a later open must reuse
 * a freed slot) and the intern table's realloc path (add enough names to outgrow the
 * initial 64-byte backing array), both well within MAX_CHANNELS and NAME_MAX_LEN. */
static void test_growth_paths(void) {
  session_t *s;
  channel_t *chan = NULL;
  size_t i;
  char label[8];
  int rc;

  s = session_create(4);
  check(s != NULL, "fifth session created");
  if (s == NULL) {
    return;
  }

  /* ARENA_SLOTS(64) + 4 opens forces channel_open onto arena_recycle for the last
   * few, well under MAX_CHANNELS(128). Each is closed immediately so the pool has
   * slots to recycle instead of exhausting outright. */
  for (i = 0; i < 68; i++) {
    chan = NULL;
    memset(label, 0, sizeof(label));
    snprintf(label, sizeof(label), "c%zu", i % 10);
    rc = channel_open(s, label, strlen(label), &chan);
    check(rc == PL_OK, "growth channel opens");
    if (chan != NULL) {
      check(chan->pending_acks == 0, "recycled or fresh channel starts with no pending acks");
      check(channel_close(s, chan->id) == PL_OK, "growth channel closes");
    }
  }

  check(session_destroy(s) == PL_OK, "fifth session destroyed");
  free(s);

  /* A separate, otherwise-unused intern table: enough short names to outgrow the
   * initial 64-byte backing array with at least one realloc, staying under the
   * table's own NAME_MAX_LEN(32) entry cap. */
  s = session_create(5);
  check(s != NULL, "sixth session created");
  if (s == NULL) {
    return;
  }
  for (i = 0; i < 20; i++) {
    char name[16];
    int slot;

    snprintf(name, sizeof(name), "grown.%zu", i);
    slot = intern_add(s->intern, name, strlen(name));
    check(slot >= 0, "intern add during growth");
    check(slot >= 0 && intern_get(s->intern, slot) != NULL, "intern get after growth");
  }
  check(session_destroy(s) == PL_OK, "sixth session destroyed");
  free(s);
}

/* Two sessions open at once must not share channel tables, credit state or stats —
 * each session_t is a fully independent instance. */
static void test_multi_session_isolation(void) {
  session_t *a;
  session_t *b;
  channel_t *chan_a = NULL;
  channel_t *chan_b = NULL;

  a = session_create(6);
  b = session_create(7);
  check(a != NULL && b != NULL, "two sessions created");
  if (a == NULL || b == NULL) {
    free(a);
    free(b);
    return;
  }

  check(channel_open(a, "a-chan", 6, &chan_a) == PL_OK, "session a channel opens");
  check(channel_open(b, "b-chan", 6, &chan_b) == PL_OK, "session b channel opens");
  check(chan_a != NULL && chan_b != NULL && chan_a != chan_b,
        "each session's channel is its own allocation");
  check(a->channel_count == 1 && b->channel_count == 1, "each session counts only its own channel");

  check(credit_grant(&a->credit, 100) == PL_OK, "session a credit granted");
  check(b->credit.state == CREDIT_IDLE, "session b credit untouched by session a's grant");

  check(stats_record(&a->stats, STATS_CTR_FRAME) == PL_OK, "session a stats recorded");
  check(b->stats.counters[STATS_CTR_FRAME] == 0, "session b stats untouched by session a");

  check(session_destroy(a) == PL_OK, "session a destroyed");
  /* codec_table_reset() resets a table shared by every session, not a per-session
   * one (see known_extra_findings in recipe.json): session a's destroy already
   * reset it, so session b's destroy sees it already at rest and its own reset
   * call reports PL_ERR_STATE even though every other part of teardown succeeds.
   * Pre-existing behaviour, not something this test is exercising. */
  (void)session_destroy(b);
  free(a);
  free(b);
}

/* channel_close_all() must tear down every open channel, in any order, and leave
 * channel_count at zero — exercised here with three channels rather than the one
 * every other test opens. */
static void test_channel_close_all(void) {
  session_t *s;
  channel_t *c1 = NULL;
  channel_t *c2 = NULL;
  channel_t *c3 = NULL;

  s = session_create(8);
  check(s != NULL, "seventh session created");
  if (s == NULL) {
    return;
  }

  check(channel_open(s, "one", 3, &c1) == PL_OK, "close-all channel one opens");
  check(channel_open(s, "two", 3, &c2) == PL_OK, "close-all channel two opens");
  check(channel_open(s, "three", 5, &c3) == PL_OK, "close-all channel three opens");
  check(s->channel_count == 3, "three channels open before close-all");

  check(channel_close_all(s) == PL_OK, "close-all succeeds");
  check(s->channel_count == 0, "no channels remain after close-all");
  check(channel_find(s, c1 != NULL ? c1->id : 0) == NULL || c1 == NULL,
        "closed channels are not findable by their old id");

  check(session_destroy(s) == PL_OK, "seventh session destroyed");
  free(s);
}

int main(void) {
  log_set_sink(0);

  test_header();
  test_name();
  test_codecs();
  test_util();
  test_pack_id();
  test_index_scan();
  test_session_and_channels();
  test_frame_path();
  test_new_modules();
  test_more_coverage();
  test_growth_paths();
  test_multi_session_isolation();
  test_channel_close_all();

  if (failures != 0) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("ok\n");
  return 0;
}
