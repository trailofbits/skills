/* Benign round trip: handshake, one data frame, spool, and four rejections that
 * hold for well-formed input. Exits non-zero on the first surprise. */

#include "sgl.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "smoke: failed %s at line %d\n", #cond, __LINE__);        \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static size_t build_frame(unsigned char *out, const unsigned char *key, uint32_t nonce,
                          uint8_t flags, uint32_t seq, const unsigned char *payload,
                          size_t plen) {
  out[0] = SGL_MAGIC0;
  out[1] = SGL_MAGIC1;
  out[2] = SGL_VERSION;
  out[3] = flags;
  out[4] = (unsigned char)(seq >> 24);
  out[5] = (unsigned char)(seq >> 16);
  out[6] = (unsigned char)(seq >> 8);
  out[7] = (unsigned char)seq;
  out[8] = (unsigned char)(plen >> 8);
  out[9] = (unsigned char)(plen & 0xff);
  if (plen > 0 && payload != NULL) {
    memcpy(out + SGL_HEADER_LEN, payload, plen);
  }
  sgl_tag_compute(key, nonce, out + SGL_HEADER_LEN, plen, out + SGL_HEADER_LEN + plen);
  return (size_t)SGL_HEADER_LEN + plen + SGL_TAG_LEN;
}

static size_t put_field(unsigned char *p, unsigned char kind, const char *name,
                        const unsigned char *value, size_t vlen) {
  size_t nlen = strlen(name);

  p[0] = kind;
  p[1] = (unsigned char)nlen;
  memcpy(p + 2, name, nlen);
  p[2 + nlen] = (unsigned char)(vlen >> 8);
  p[3 + nlen] = (unsigned char)(vlen & 0xff);
  if (vlen > 0 && value != NULL) {
    memcpy(p + 4 + nlen, value, vlen);
  }
  return 4 + nlen + vlen;
}

int main(void) {
  const char *spool = "sgl-smoke-spool.tmp";
  unsigned char key[SGL_KEY_LEN];
  unsigned char frame[SGL_HEADER_LEN + SGL_MAX_PAYLOAD + SGL_TAG_LEN];
  unsigned char payload[512];
  unsigned char group[9];
  const sgl_record *rec;
  sgl_session *session;
  size_t i;
  size_t used;
  size_t flen;
  int leaves = 0;

  for (i = 0; i < SGL_KEY_LEN; i++) {
    key[i] = (unsigned char)(0x40 + i);
  }

  session = sgl_session_new(key);
  CHECK(session != NULL);
  CHECK(sgl_session_state(session) == SGL_ST_INIT);

  flen = build_frame(frame, key, sgl_session_nonce(session), SGL_FLAG_HELLO, 1, NULL, 0);
  CHECK(sgl_feed(session, frame, flen) == SGL_OK);
  CHECK(sgl_session_state(session) == SGL_ST_HELLO);

  flen = build_frame(frame, key, sgl_session_nonce(session), SGL_FLAG_READY, 2, NULL, 0);
  CHECK(sgl_feed(session, frame, flen) == SGL_OK);
  CHECK(sgl_session_state(session) == SGL_ST_READY);

  group[0] = SGL_KIND_GROUP;
  group[1] = 0;
  group[2] = 3;
  group[3] = SGL_KIND_TEXT;
  group[4] = 0;
  group[5] = 0;
  group[6] = SGL_KIND_TEXT;
  group[7] = 0;
  group[8] = 0;
  CHECK(sgl_group_walk(group, sizeof(group), 0, &leaves) == SGL_OK);
  CHECK(leaves == 2);

  used = 0;
  used += put_field(payload + used, SGL_KIND_SCOPE, "scope",
                    (const unsigned char *)"metrics.host", 12);
  used += put_field(payload + used, SGL_KIND_TEXT, "cpu.load", (const unsigned char *)"0.42", 4);
  used += put_field(payload + used, SGL_KIND_GROUP, "nested", group, sizeof(group));
  used += put_field(payload + used, SGL_KIND_TEXT, "mem.free", (const unsigned char *)"91", 2);

  flen = build_frame(frame, key, sgl_session_nonce(session), 0, 3, payload, used);
  CHECK(sgl_feed(session, frame, flen) == SGL_OK);

  rec = sgl_session_record(session);
  CHECK(rec != NULL);
  CHECK(rec->field_count == 4);
  CHECK(rec->seq == 3);
  CHECK(strcmp(rec->scope, "metrics.host") == 0);
  CHECK(strcmp(rec->fields[1].name, "cpu.load") == 0);
  CHECK(rec->fields[1].value_len == 4);
  CHECK(memcmp(rec->fields[1].value, "0.42", 4) == 0);
  CHECK(strcmp(sgl_session_last_path(session), "metrics.host/mem.free") == 0);
  CHECK(sgl_session_retired(session) == 0);

  /* Rejections that hold for any well-formed peer. */
  flen = build_frame(frame, key, sgl_session_nonce(session), 0, 4, payload, used);
  frame[0] = 0x00;
  CHECK(sgl_feed(session, frame, flen) == SGL_E_FORMAT);

  flen = build_frame(frame, key, sgl_session_nonce(session), 0, 4, payload, used);
  frame[2] = SGL_VERSION + 1;
  CHECK(sgl_feed(session, frame, flen) == SGL_E_FORMAT);

  flen = build_frame(frame, key, sgl_session_nonce(session), 0, 4, payload, used);
  frame[flen - 1] ^= 0xff;
  CHECK(sgl_feed(session, frame, flen) == SGL_E_AUTH);

  CHECK(sgl_name_check("cpu.load") == SGL_OK);
  CHECK(sgl_name_check("cpu/load") == SGL_E_FORMAT);

  (void)unlink(spool);
  CHECK(sgl_spool_write(spool, rec) == SGL_OK);
  CHECK(sgl_spool_write(spool, rec) == SGL_E_IO);
  CHECK(unlink(spool) == 0);

  sgl_session_free(session);
  printf("smoke: ok\n");
  return 0;
}
