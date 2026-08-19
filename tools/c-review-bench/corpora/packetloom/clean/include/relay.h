#ifndef PL_RELAY_H
#define PL_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

/* Wire framing: magic(2) version(1) priority(1) total_len(4) payload
 * Fragment header: chan(2) index(1) count(1) priority(1) pad(3) payload
 *
 * Control message bodies, one op byte followed by the fields below. Every handler
 * in relay.c's g_dispatch table may read up to its declared min_len unconditionally;
 * anything past that is validated inside the handler itself.
 *
 *   OP_OPEN_CHANNEL   (1)  chan_id(2) label_len(1) label[label_len]
 *   OP_CLOSE_CHANNEL  (2)  chan_id(2) selector(1)
 *   OP_SET_LABEL      (3)  chan_id(2) label_len(1) label[label_len]
 *   OP_CLOSE_SESSION  (4)  (no body)
 *   OP_DECODE_FIELD   (5)  field_len(2) field[field_len]
 *   OP_SET_PEER       (6)  chan_id(2) name_len(1) name[name_len]
 *   OP_ARM_TIMER      (7)  chan_id(2) delay(1)
 *   OP_SET_OPTION     (8)  text_len(2) text[text_len]        — see optparse.c
 *   OP_STATS_MERGE    (9)  (counter_id(1) delta_be32(4))*    — see stats.c
 *   OP_CREDIT_GRANT   (10) chan_id(2) amount_be16(2)         — see credit.c
 *   OP_FAST_FRAGMENT  (11) chan_id(2) index(1) payload       — see reasm_oo.c
 *   OP_BULK_OPTION    (12) count(1) (len_be16(2) text[len])* — see optparse.c
 *   OP_RESIZE_WINDOW  (13) chan_id(2) new_window_be16(2)     — see channel.c
 *   OP_PEEK_FRAGMENT  (14) index(1)                          — see reasm_oo.c
 *   OP_STATS_NAME     (15) counter_id(1)                     — see stats.c
 */

#define PL_MAGIC0 0x50
#define PL_MAGIC1 0x4C
#define PL_VERSION 3

#define OP_OPEN_CHANNEL 1
#define OP_CLOSE_CHANNEL 2
#define OP_SET_LABEL 3
#define OP_CLOSE_SESSION 4
#define OP_DECODE_FIELD 5
#define OP_SET_PEER 6
#define OP_ARM_TIMER 7
#define OP_SET_OPTION 8
#define OP_STATS_MERGE 9
#define OP_CREDIT_GRANT 10
#define OP_FAST_FRAGMENT 11
#define OP_BULK_OPTION 12
#define OP_RESIZE_WINDOW 13
#define OP_PEEK_FRAGMENT 14
#define OP_STATS_NAME 15
#define OP_POOL_GRANT 16
#define OP_LIST_CHANNELS 17

#define CODEC_RAW 0
#define CODEC_RLE 1
#define CODEC_DELTA 2
#define CODEC_VARINT 3
#define CODEC_DICT 4
#define CODEC_CHUNKED 5
#define CODEC_ZIGZAG 6

#define CH_FLAG_OPEN 0x01
#define CH_FLAG_PRIORITY 0x02

#define STATS_CTR_FRAME 0
#define STATS_CTR_CONTROL 1
#define STATS_CTR_CHANNEL_OPEN 2
#define STATS_CTR_CHANNEL_CLOSE 3
#define STATS_CTR_RETRY 4

enum {
  PL_OK = 0,
  PL_ERR = -1,
  PL_ERR_SHORT = -2,
  PL_ERR_FORMAT = -3,
  PL_ERR_LIMIT = -4,
  PL_ERR_STATE = -5,
  PL_ERR_NOMEM = -6,
  PL_ERR_LABEL_TOO_LONG = -7,
  PL_ERR_NO_CHANNEL = -8
};

typedef struct {
  uint8_t version;
  uint8_t priority;
  uint32_t total_len;
  const uint8_t *payload;
  size_t payload_len;
} frame_hdr_t;

typedef struct {
  uint16_t chan;
  uint8_t index;
  uint8_t count;
  uint8_t priority;
} frag_hdr_t;

typedef struct channel_s {
  uint16_t id;
  uint8_t flags;
  uint8_t refcount;
  uint16_t window;
  uint16_t pending_acks;
  uint8_t ack_byte;
  uint16_t retry_slots[MAX_WINDOW];
  char label[LABEL_MAX];
  char *heap_label;
} channel_t;

typedef struct {
  uint8_t scratch[SCRATCH_MAX];
  size_t scratch_len;
} codec_ctx_t;

typedef struct {
  const char *name;
  uint8_t id;
  int (*decode)(codec_ctx_t *ctx, const uint8_t *src, size_t len, uint8_t *out, size_t *out_len);
} codec_t;

typedef struct arena_s arena_t;
typedef struct intern_s intern_t;
typedef struct session_s session_t;
typedef struct timer_wheel_s timer_wheel_t;

typedef void (*frame_hook_fn)(session_t *s, const uint8_t *payload, size_t len);

/* Flow-control credit scheduler (credit.c). Three states: IDLE (no grant
 * outstanding), ARMED (a grant is outstanding and may be spent), DRAINING (the
 * grant is being spent down and must be reclaimed before a new one is armed). */
typedef enum {
  CREDIT_IDLE = 0,
  CREDIT_ARMED = 1,
  CREDIT_DRAINING = 2
} credit_state_t;

typedef struct {
  credit_state_t state;
  uint32_t granted;
  uint32_t spent;
  uint32_t history[CREDIT_HISTORY];
  size_t history_count;
} credit_sched_t;

/* Telemetry counters (stats.c). */
typedef struct {
  uint32_t counters[STATS_MAX_COUNTERS];
} stats_t;

/* Out-of-order fragment cache (reasm_oo.c). */
typedef struct {
  uint8_t used;
  uint8_t index;
  uint16_t len;
  uint8_t data[OO_SLOT_CAP];
} oo_slot_t;

typedef struct {
  oo_slot_t slots[REASM_OO_SLOTS];
} reasm_oo_t;

struct session_s {
  uint16_t id;
  int active;
  uint8_t *rx_buf;
  size_t rx_len;
  size_t rx_cap;
  uint8_t scratch[SCRATCH_MAX];
  channel_t *channels[MAX_CHANNELS];
  size_t channel_count;
  arena_t *arena;
  intern_t *intern;
  codec_ctx_t codec_ctx;
  frame_hook_fn on_frame; /* may call relay_close_session(s) — see relay.c */
  unsigned retry_depth;
  char peer_name[NAME_MAX_LEN];
  timer_wheel_t *timers;
  credit_sched_t credit;
  credit_sched_t pools[CREDIT_POOL_COUNT]; /* per traffic-class budgets */
  stats_t stats;
  reasm_oo_t oo;
};

/* relay.c */
int relay_on_frame(session_t *s, const uint8_t *buf, size_t len);
int relay_on_control(session_t *s, const uint8_t *buf, size_t len);
int relay_route_control(session_t *s, uint8_t op, const uint8_t *body, size_t len);
int relay_close_session(session_t *s);
int relay_schedule_retry(session_t *s, uint16_t chan_id);
int frame_dispatch_payload(session_t *s, uint8_t codec_id, const uint8_t *p, size_t len);
int control_msg_decode(session_t *s, const uint8_t *body, size_t len);
int control_msg_open(session_t *s, const uint8_t *body, size_t len);

/* session.c */
session_t *session_create(uint16_t id);
int session_init(session_t *s);
int session_destroy(session_t *s);
int session_set_peer_name(session_t *s, const char *raw, size_t raw_len);
session_t *session_lookup(uint16_t id);
session_t *session_lookup_checked(uint16_t id);
int session_reserve_rx(session_t *s, size_t need);
int session_window_credit(session_t *s, uint16_t chan_id, uint32_t off, uint32_t len);

/* frame.c */
int frame_parse_header(const uint8_t *buf, size_t len, frame_hdr_t *out);
int frame_parse_name(const uint8_t *p, size_t avail, char *out, size_t out_cap);
int frame_set_rx_len(session_t *s, size_t n);

/* reassembly.c */
int reasm_on_fragment_header(session_t *s, const uint8_t *buf, size_t avail, frag_hdr_t *out);
int reasm_absorb(session_t *s, const frag_hdr_t *fh, const uint8_t *p, size_t len);
int reasm_scan_index(const uint8_t *buf, size_t avail, uint32_t *a, uint32_t *b, uint32_t *c);

/* channel.c */
int channel_open(session_t *s, const char *label, size_t label_len, channel_t **out);
int channel_close(session_t *s, uint16_t chan_id);
int channel_close_all(session_t *s);
int channel_set_label(channel_t *chan, const char *new_label);
int channel_send(session_t *s, channel_t *chan, uint16_t slot);
int channel_on_ack(session_t *s, channel_t *chan, uint16_t slot);
int channel_inject_control(session_t *s, channel_t *chan, uint16_t slot);
int channel_resize_window(session_t *s, channel_t *chan, uint16_t new_window);
uint8_t channel_pack_id(uint16_t chan_id, uint8_t flags);
uint16_t channel_unpack_id(uint8_t packed);
channel_t *channel_find(session_t *s, uint16_t chan_id);
channel_t *channel_find_by_label(session_t *s, const char *label, size_t label_len);
int channel_list_ids(session_t *s, uint16_t *out, size_t out_cap, size_t *out_count);

/* codec_table.c */
void codec_init_all(void);
int codec_table_reset(void);
const codec_t *codec_lookup(uint8_t id);
int codec_raw_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out, size_t *out_len);
int codec_rle_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out, size_t *out_len);
int codec_delta_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                       size_t *out_len);
int codec_varint_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                        size_t *out_len);
int codec_dict_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                      size_t *out_len);
int codec_chunked_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                         size_t *out_len);
int codec_zigzag_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                        size_t *out_len);

/* arena.c */
arena_t *arena_create(void);
void arena_destroy(arena_t *a);
channel_t *arena_alloc(arena_t *a);
void arena_free(arena_t *a, channel_t *slot);
channel_t *arena_recycle(arena_t *a);
int arena_reset(arena_t *a);

/* intern.c */
intern_t *intern_create(void);
void intern_destroy(intern_t *t);
int intern_add(intern_t *t, const char *name, size_t len);
const char *intern_get(const intern_t *t, int slot);
int intern_lookup(const intern_t *t, const char *name);
int intern_clear(intern_t *t);

/* log.c */
int log_field(session_t *s, int name_slot, const char *tag);
int log_write(const char *fmt, const char *arg);
int log_flush(void);
void log_set_sink(int enabled);

/* util.c */
void copy_field(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t len);
uint32_t rd_be32(const uint8_t *p);
uint16_t rd_be16(const uint8_t *p);

/* timer.c */
timer_wheel_t *timer_wheel_create(void);
void timer_wheel_destroy(timer_wheel_t *tw);
int timer_wheel_arm(timer_wheel_t *tw, uint16_t chan_id, unsigned delay);
int timer_wheel_cancel(timer_wheel_t *tw, uint16_t chan_id);
int timer_wheel_tick(timer_wheel_t *tw, session_t *s);

/* credit.c */
void credit_init(credit_sched_t *cs);
int credit_grant(credit_sched_t *cs, uint32_t amount);
int credit_spend(credit_sched_t *cs, uint32_t amount);
int credit_reclaim(credit_sched_t *cs);
int credit_grant_priority(credit_sched_t *cs, uint32_t amount);
credit_sched_t *credit_pool_for(session_t *s, uint8_t class_id);
void credit_pools_init(session_t *s);
void credit_pools_reclaim_all(session_t *s);

/* optparse.c */
int opt_apply(session_t *s, const char *text, size_t len);
int opt_apply_bulk(session_t *s, const uint8_t *buf, size_t avail);

/* stats.c */
void stats_init(stats_t *st);
int stats_record(stats_t *st, unsigned counter_id);
int stats_merge_snapshot(stats_t *st, const uint8_t *buf, size_t avail);
int stats_dump(const stats_t *st, uint8_t *out, size_t out_cap);
int stats_name_copy(unsigned counter_id, char *out, size_t out_cap);

/* backoff.c */
unsigned backoff_next(unsigned attempt);
unsigned backoff_max_attempt(void);

/* reasm_oo.c */
void reasm_oo_init(reasm_oo_t *oo);
int reasm_oo_stash(reasm_oo_t *oo, uint8_t index, const uint8_t *p, size_t len);
int reasm_fast_absorb(session_t *s, uint16_t chan_id, uint8_t index, const uint8_t *p, size_t len);
int reasm_oo_peek(const reasm_oo_t *oo, uint8_t index, uint8_t *out, size_t out_cap);

#endif /* PL_RELAY_H */
