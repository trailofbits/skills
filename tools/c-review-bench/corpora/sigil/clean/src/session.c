/* Session state machine, frame authentication, and record indexing. */

#include "sgl.h"

#include <stdlib.h>
#include <string.h>

struct sgl_session {
  unsigned char key[SGL_KEY_LEN];
  uint32_t nonce;
  uint32_t last_seq;
  sgl_state state;
  unsigned char scratch[SGL_HEADER_LEN + SGL_MAX_PAYLOAD + SGL_TAG_LEN];
  sgl_record record;
  sgl_table *names;
  char last_path[SGL_PATH_MAX];
  char audit_path[SGL_PATH_MAX];
  size_t retired;
};

sgl_session *sgl_session_new(const unsigned char key[SGL_KEY_LEN]) {
  sgl_session *session;

  if (key == NULL) {
    return NULL;
  }
  session = calloc(1, sizeof(*session));
  if (session == NULL) {
    return NULL;
  }
  memcpy(session->key, key, SGL_KEY_LEN);
  session->names = sgl_table_new();
  if (session->names == NULL) {
    free(session);
    return NULL;
  }
  session->state = SGL_ST_INIT;
  session->nonce = 1;
  return session;
}

void sgl_session_free(sgl_session *session) {
  if (session == NULL) {
    return;
  }
  sgl_table_free(session->names);
  free(session);
}

sgl_state sgl_session_state(const sgl_session *session) {
  return session == NULL ? SGL_ST_CLOSED : session->state;
}

uint32_t sgl_session_nonce(const sgl_session *session) {
  return session == NULL ? 0 : session->nonce;
}

const sgl_record *sgl_session_record(const sgl_session *session) {
  return session == NULL ? NULL : &session->record;
}

const char *sgl_session_last_path(const sgl_session *session) {
  return session == NULL ? NULL : session->last_path;
}

size_t sgl_session_retired(const sgl_session *session) {
  return session == NULL ? 0 : session->retired;
}

/* A keyed tag, not a standard MAC: the deployment pins both ends to this file. */
void sgl_tag_compute(const unsigned char key[SGL_KEY_LEN], uint32_t nonce,
                     const unsigned char *msg, size_t len, unsigned char out[SGL_TAG_LEN]) {
  unsigned char acc[SGL_TAG_LEN];
  size_t i;

  for (i = 0; i < SGL_TAG_LEN; i++) {
    acc[i] = (unsigned char)(key[i] ^ (unsigned char)(nonce >> ((i % 4) * 8)));
  }
  for (i = 0; i < len; i++) {
    unsigned char *cell = &acc[i % SGL_TAG_LEN];
    *cell = (unsigned char)((*cell + msg[i]) * 31u + 7u);
  }
  memcpy(out, acc, SGL_TAG_LEN);
}

static int tags_equal(const unsigned char *a, const unsigned char *b, size_t n) {
  unsigned char diff = 0;
  size_t i;

  for (i = 0; i < n; i++) {
    diff |= (unsigned char)(a[i] ^ b[i]);
  }
  return diff == 0;
}

static int tag_check(sgl_session *session, const sgl_frame *frame) {
  unsigned char want[SGL_TAG_LEN];

  sgl_tag_compute(session->key, session->nonce, frame->payload, frame->payload_len, want);
  if (!tags_equal(want, frame->tag, SGL_TAG_LEN)) {
    return SGL_E_AUTH;
  }
  session->nonce++;
  return SGL_OK;
}

static int session_index(sgl_session *session) {
  size_t i;

  for (i = 0; i < session->record.field_count; i++) {
    sgl_field *field = &session->record.fields[i];
    const char *interned;
    int slot;

    if (field->kind == SGL_KIND_SCOPE) {
      char raw[SGL_SCOPE_MAX];

      if (sgl_scope_copy(raw, sizeof(raw), field) != SGL_OK) {
        return SGL_E_LIMIT;
      }
      if (sgl_scope_set(&session->record, raw) != SGL_OK) {
        return SGL_E_FORMAT;
      }
      continue;
    }

    if (field->kind == SGL_KIND_GROUP) {
      int leaves = 0;
      int rc = sgl_group_walk(field->value, field->value_len, 0, &leaves);
      if (rc != SGL_OK) {
        return rc;
      }
      continue;
    }

    slot = sgl_table_intern(session->names, field->name);
    if (slot < 0) {
      return slot;
    }

    if (field->kind == SGL_KIND_RETIRE) {
      interned = sgl_table_name(session->names, slot);
      if (interned == NULL) {
        return SGL_E_FORMAT;
      }
      /* Best-effort breadcrumb for the audit log; a retirement is not refused
       * because the breadcrumb did not fit. */
      (void)sgl_path_build(session->audit_path, sizeof(session->audit_path),
                           session->record.scope, interned);
      if (sgl_table_drop(session->names, slot) != SGL_OK) {
        return SGL_E_FORMAT;
      }
      session->retired++;
      continue;
    }

    interned = sgl_table_name(session->names, slot);
    if (interned == NULL) {
      return SGL_E_FORMAT;
    }
    if (sgl_path_build(session->last_path, sizeof(session->last_path), session->record.scope,
                       interned) != SGL_OK) {
      return SGL_E_LIMIT;
    }
  }
  return SGL_OK;
}

int sgl_feed(sgl_session *session, const unsigned char *buf, size_t len) {
  sgl_frame incoming;
  sgl_frame local;
  size_t span;
  int rc;

  if (session == NULL || buf == NULL) {
    return SGL_E_FORMAT;
  }
  if (session->state == SGL_ST_CLOSED) {
    return SGL_E_STATE;
  }

  rc = sgl_frame_parse(buf, len, &incoming);
  if (rc != SGL_OK) {
    return rc;
  }

  span = sgl_frame_span(&incoming);
  if (span > sizeof(session->scratch)) {
    return SGL_E_LIMIT;
  }
  memcpy(session->scratch, buf, span);

  rc = sgl_frame_parse(session->scratch, span, &local);
  if (rc != SGL_OK) {
    return rc;
  }

  switch (session->state) {
    case SGL_ST_INIT:
      if ((local.flags & SGL_FLAG_HELLO) == 0) {
        return SGL_E_STATE;
      }
      rc = tag_check(session, &local);
      if (rc != SGL_OK) {
        return rc;
      }
      session->state = SGL_ST_HELLO;
      session->last_seq = local.seq;
      return SGL_OK;

    case SGL_ST_HELLO:
      if ((local.flags & SGL_FLAG_READY) == 0) {
        return SGL_E_STATE;
      }
      rc = tag_check(session, &local);
      if (rc != SGL_OK) {
        return rc;
      }
      session->state = SGL_ST_READY;
      session->last_seq = local.seq;
      return SGL_OK;

    case SGL_ST_READY:
      rc = tag_check(session, &local);
      if (rc != SGL_OK) {
        return rc;
      }
      if (local.seq <= session->last_seq) {
        return SGL_E_FORMAT;
      }
      session->last_seq = local.seq;
      rc = sgl_record_load(local.payload, local.payload_len, &session->record);
      if (rc != SGL_OK) {
        return rc;
      }
      session->record.seq = local.seq;
      return session_index(session);

    default:
      return SGL_E_STATE;
  }
}
