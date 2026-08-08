#ifndef PL_RELAY_H
#define PL_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

/* Wire framing: magic(2) version(1) priority(1) total_len(4) payload
 * Fragment header: chan(2) index(1) count(1) priority(1) pad(3) payload */

#define PL_MAGIC0 0x50
#define PL_MAGIC1 0x4C
#define PL_VERSION 3

#define OP_OPEN_CHANNEL 1
#define OP_CLOSE_CHANNEL 2
#define OP_SET_LABEL 3
#define OP_CLOSE_SESSION 4
#define OP_DECODE_FIELD 5
#define OP_SET_PEER 6

#define CODEC_RAW 0
#define CODEC_RLE 1
#define CODEC_DELTA 2
#define CODEC_VARINT 3
#define CODEC_DICT 4
#define CODEC_CHUNKED 5

#define CH_FLAG_OPEN 0x01
#define CH_FLAG_PRIORITY 0x02

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

typedef void (*frame_hook_fn)(session_t *s, const uint8_t *payload, size_t len);

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
uint8_t channel_pack_id(uint16_t chan_id, uint8_t flags);
uint16_t channel_unpack_id(uint8_t packed);
channel_t *channel_find(session_t *s, uint16_t chan_id);

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

#endif /* PL_RELAY_H */
