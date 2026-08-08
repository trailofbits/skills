/* Field decoding. Layout per field: kind(1) name_len(1) name vlen(2) value */

#include "sgl.h"

#include <string.h>

int sgl_field_decode(const unsigned char *p, size_t avail, sgl_field *out, size_t *used) {
  size_t name_len;
  size_t value_len;

  if (p == NULL || out == NULL || used == NULL) {
    return SGL_E_FORMAT;
  }
  if (avail < 2) {
    return SGL_E_SHORT;
  }

  name_len = p[1];
  if (name_len == 0 || name_len >= SGL_NAME_MAX) {
    return SGL_E_FORMAT;
  }
  if (avail < 2 + name_len + 2) {
    return SGL_E_SHORT;
  }

  value_len = (size_t)(((size_t)p[2 + name_len] << 8) | (size_t)p[3 + name_len]);
  if (value_len > SGL_VALUE_MAX) {
    return SGL_E_LIMIT;
  }
  if (avail < 4 + name_len + value_len) {
    return SGL_E_SHORT;
  }

  memset(out, 0, sizeof(*out));
  out->kind = p[0];
  memcpy(out->name, p + 2, name_len);
  out->name[name_len] = '\0';
  memcpy(out->value, p + 4 + name_len, value_len);
  out->value_len = value_len;

  *used = 4 + name_len + value_len;
  return SGL_OK;
}

int sgl_record_load(const unsigned char *payload, size_t len, sgl_record *rec) {
  size_t off = 0;

  if (rec == NULL) {
    return SGL_E_FORMAT;
  }
  memset(rec, 0, sizeof(*rec));
  if (payload == NULL && len != 0) {
    return SGL_E_FORMAT;
  }

  while (off < len) {
    sgl_field *slot;
    size_t used = 0;
    int rc;

    if (rec->field_count >= SGL_MAX_FIELDS) {
      return SGL_E_LIMIT;
    }
    slot = &rec->fields[rec->field_count];
    rc = sgl_field_decode(payload + off, len - off, slot, &used);
    if (rc != SGL_OK) {
      return rc;
    }
    if (used == 0) {
      return SGL_E_FORMAT;
    }
    off += used;
    rec->field_count++;
  }
  return SGL_OK;
}
