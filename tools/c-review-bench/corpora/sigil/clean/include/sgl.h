#ifndef SGL_H
#define SGL_H

#include <stddef.h>
#include <stdint.h>

/* Wire framing: magic(2) version(1) flags(1) seq(4) payload_len(2) payload tag(16) */
#define SGL_MAGIC0 0x53
#define SGL_MAGIC1 0x47
#define SGL_VERSION 2
#define SGL_HEADER_LEN 10
#define SGL_TAG_LEN 16
#define SGL_KEY_LEN 16
#define SGL_MAX_PAYLOAD 65535 /* the 16-bit length field is the only limit */

#define SGL_NAME_MAX 32
#define SGL_VALUE_MAX 96
#define SGL_SCOPE_MAX 48
#define SGL_PATH_MAX 96
#define SGL_MAX_FIELDS 12
#define SGL_GROUP_DEPTH_MAX 6
#define SGL_SEP '/'

#define SGL_FLAG_HELLO 0x01
#define SGL_FLAG_READY 0x02
#define SGL_FLAG_GROUP 0x04

#define SGL_KIND_TEXT 1
#define SGL_KIND_SCOPE 2
#define SGL_KIND_RETIRE 3
#define SGL_KIND_GROUP 4

enum {
  SGL_OK = 0,
  SGL_E_SHORT = -1,
  SGL_E_FORMAT = -2,
  SGL_E_LIMIT = -3,
  SGL_E_AUTH = -4,
  SGL_E_MEM = -5,
  SGL_E_STATE = -6,
  SGL_E_IO = -7
};

typedef struct {
  uint8_t version;
  uint8_t flags;
  uint32_t seq;
  uint16_t payload_len;
  const unsigned char *payload;
  const unsigned char *tag;
} sgl_frame;

typedef struct {
  char name[SGL_NAME_MAX];
  unsigned char value[SGL_VALUE_MAX];
  size_t value_len;
  uint8_t kind;
} sgl_field;

typedef struct {
  char scope[SGL_SCOPE_MAX];
  sgl_field fields[SGL_MAX_FIELDS];
  size_t field_count;
  uint32_t seq;
} sgl_record;

typedef enum { SGL_ST_INIT = 0, SGL_ST_HELLO, SGL_ST_READY, SGL_ST_CLOSED } sgl_state;

typedef struct sgl_table sgl_table;
typedef struct sgl_session sgl_session;

/* frame.c */
int sgl_frame_parse(const unsigned char *buf, size_t len, sgl_frame *out);
size_t sgl_frame_span(const sgl_frame *frame);

/* field.c */
int sgl_field_decode(const unsigned char *p, size_t avail, sgl_field *out, size_t *used);
int sgl_record_load(const unsigned char *payload, size_t len, sgl_record *rec);

/* table.c */
sgl_table *sgl_table_new(void);
void sgl_table_free(sgl_table *table);
int sgl_table_intern(sgl_table *table, const char *name);
const char *sgl_table_name(const sgl_table *table, int slot);
int sgl_table_drop(sgl_table *table, int slot);
size_t sgl_table_count(const sgl_table *table);

/* path.c */
int sgl_name_check(const char *name);
int sgl_scope_copy(char *dst, size_t dst_size, const sgl_field *field);
int sgl_scope_set(sgl_record *rec, const char *raw);
int sgl_path_build(char *out, size_t out_size, const char *scope, const char *name);

/* session.c */
sgl_session *sgl_session_new(const unsigned char key[SGL_KEY_LEN]);
void sgl_session_free(sgl_session *session);
sgl_state sgl_session_state(const sgl_session *session);
uint32_t sgl_session_nonce(const sgl_session *session);
const sgl_record *sgl_session_record(const sgl_session *session);
const char *sgl_session_last_path(const sgl_session *session);
size_t sgl_session_retired(const sgl_session *session);
void sgl_tag_compute(const unsigned char key[SGL_KEY_LEN], uint32_t nonce,
                     const unsigned char *msg, size_t len, unsigned char out[SGL_TAG_LEN]);
int sgl_feed(sgl_session *session, const unsigned char *buf, size_t len);

/* spool.c */
int sgl_spool_write(const char *path, const sgl_record *rec);
int sgl_group_walk(const unsigned char *p, size_t len, int depth, int *leaves);

#endif /* SGL_H */
