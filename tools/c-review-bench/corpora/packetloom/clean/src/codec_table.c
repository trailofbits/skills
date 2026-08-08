/* The codec table.
 *
 * Six decoders, all with the same shape: validate the wire-supplied length against the
 * capacity of the buffer this decoder actually writes into, then copy. Two of them
 * (dict, chunked) stage through the shared ctx scratch; the other four write straight
 * into the caller's output buffer. The buffer a decoder checks and the buffer it writes
 * are always the same one.
 */

#include "relay.h"

#include <string.h>

static codec_t g_table[MAX_CODECS];
static size_t g_registered = 0;

static void register_codec(const codec_t *c) {
  if (g_registered >= MAX_CODECS || c == NULL) {
    return;
  }
  g_table[g_registered++] = *c;
}

int codec_raw_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                     size_t *out_len) {
  uint8_t dst[64];
  size_t field_len;

  (void)c;
  if (src == NULL || out == NULL || out_len == NULL || len < 2) {
    return PL_ERR_FORMAT;
  }
  field_len = rd_be16(src);
  if (field_len > len - 2) {
    return PL_ERR_SHORT;
  }
  if (field_len > sizeof(dst)) {
    return PL_ERR_LIMIT;
  }
  memcpy(dst, src + 2, field_len);
  memcpy(out, dst, field_len);
  *out_len = field_len;
  return PL_OK;
}

int codec_rle_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                     size_t *out_len) {
  uint8_t dst[64];
  size_t field_len;
  size_t i;

  (void)c;
  if (src == NULL || out == NULL || out_len == NULL || len < 3) {
    return PL_ERR_FORMAT;
  }
  field_len = rd_be16(src);
  if (field_len > sizeof(dst)) {
    return PL_ERR_LIMIT;
  }
  for (i = 0; i < field_len; i++) {
    dst[i] = src[2];
  }
  memcpy(out, dst, field_len);
  *out_len = field_len;
  return PL_OK;
}

int codec_delta_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                       size_t *out_len) {
  uint8_t dst[64];
  size_t field_len;
  size_t i;
  uint8_t acc = 0;

  (void)c;
  if (src == NULL || out == NULL || out_len == NULL || len < 2) {
    return PL_ERR_FORMAT;
  }
  field_len = rd_be16(src);
  if (field_len > len - 2) {
    return PL_ERR_SHORT;
  }
  if (field_len > sizeof(dst)) {
    return PL_ERR_LIMIT;
  }
  for (i = 0; i < field_len; i++) {
    acc = (uint8_t)(acc + src[2 + i]);
    dst[i] = acc;
  }
  memcpy(out, dst, field_len);
  *out_len = field_len;
  return PL_OK;
}

int codec_varint_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                        size_t *out_len) {
  uint8_t dst[64];
  uint32_t units;
  size_t bytes;

  (void)c;
  if (src == NULL || out == NULL || out_len == NULL || len < 4) {
    return PL_ERR_FORMAT;
  }
  units = rd_be32(src);
  /* Each unit expands to four output bytes. Bound the unit count rather than the
   * product, so the multiplication has nothing to overflow. */
  if (units > sizeof(dst) / 4) {
    return PL_ERR_LIMIT;
  }
  bytes = (size_t)units * 4;
  if (bytes > len - 4) {
    return PL_ERR_SHORT;
  }
  memcpy(dst, src + 4, bytes);
  memcpy(out, dst, bytes);
  *out_len = bytes;
  return PL_OK;
}

int codec_dict_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                      size_t *out_len) {
  uint8_t dst[64];
  const uint8_t *field;
  size_t field_len;

  if (c == NULL || src == NULL || out == NULL || out_len == NULL || len < 2) {
    return PL_ERR_FORMAT;
  }
  field_len = rd_be16(src);
  if (field_len > len - 2) {
    return PL_ERR_SHORT;
  }
  if (field_len > sizeof(dst)) {
    return PL_ERR_LIMIT;
  }
  field = src + 2;
  memcpy(dst, field, field_len);
  memcpy(out, dst, field_len);
  *out_len = field_len;
  return PL_OK;
}

int codec_chunked_decode(codec_ctx_t *c, const uint8_t *src, size_t len, uint8_t *out,
                         size_t *out_len) {
  const uint8_t *field;
  size_t field_len;

  if (c == NULL || src == NULL || out == NULL || out_len == NULL || len < 2) {
    return PL_ERR_FORMAT;
  }
  field_len = rd_be16(src);
  if (field_len > len - 2) {
    return PL_ERR_SHORT;
  }
  if (field_len > sizeof(c->scratch)) {
    return PL_ERR_LIMIT;
  }
  field = src + 2;
  memcpy(c->scratch, field, field_len);
  c->scratch_len = field_len;
  memcpy(out, c->scratch, field_len);
  *out_len = field_len;
  return PL_OK;
}

static const codec_t raw_codec = {"raw", CODEC_RAW, codec_raw_decode};
static const codec_t rle_codec = {"rle", CODEC_RLE, codec_rle_decode};
static const codec_t delta_codec = {"delta", CODEC_DELTA, codec_delta_decode};
static const codec_t varint_codec = {"varint", CODEC_VARINT, codec_varint_decode};
static const codec_t dict_codec = {"dict", CODEC_DICT, codec_dict_decode};
static const codec_t chunked_codec = {"chunked", CODEC_CHUNKED, codec_chunked_decode};

void codec_init_all(void) {
  g_registered = 0;
  register_codec(&raw_codec);
  register_codec(&rle_codec);
  register_codec(&delta_codec);
  register_codec(&varint_codec);
  register_codec(&dict_codec);
  register_codec(&chunked_codec);
}

int codec_table_reset(void) {
  if (g_registered == 0) {
    return PL_ERR_STATE;
  }
  memset(g_table, 0, sizeof(g_table));
  g_registered = 0;
  return PL_OK;
}

const codec_t *codec_lookup(uint8_t id) {
  size_t i;

  for (i = 0; i < g_registered; i++) {
    if (g_table[i].id == id) {
      return &g_table[i];
    }
  }
  return NULL;
}
