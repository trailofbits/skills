/* Scope and name handling. A path is scope, one separator, then a name. */

#include "sgl.h"

#include <string.h>

/* The one definition of what may appear in a name or a scope. The separator is
 * excluded, which is what keeps a path unambiguous once it is joined. */
#define SGL_IS_NAME_CH(c)                                                      \
  (((c) >= 'a' && (c) <= 'z') || ((c) >= '0' && (c) <= '9') || (c) == '_' || (c) == '.')

int sgl_name_check(const char *name) {
  size_t i;

  if (name == NULL || name[0] == '\0') {
    return SGL_E_FORMAT;
  }
  for (i = 0; name[i] != '\0'; i++) {
    if (!SGL_IS_NAME_CH((unsigned char)name[i])) {
      return SGL_E_FORMAT;
    }
  }
  if (i >= SGL_NAME_MAX) {
    return SGL_E_LIMIT;
  }
  return SGL_OK;
}

/* Copy a scope field's bytes out as a C string. The caller's buffer is small and
 * the field's is not, so the length is checked against the destination. */
int sgl_scope_copy(char *dst, size_t dst_size, const sgl_field *field) {
  size_t n;

  if (dst == NULL || field == NULL || dst_size == 0) {
    return SGL_E_FORMAT;
  }
  n = field->value_len;
  if (n >= dst_size) {
    return SGL_E_LIMIT;
  }
  memcpy(dst, field->value, n);
  dst[n] = '\0';
  return SGL_OK;
}

int sgl_scope_set(sgl_record *rec, const char *raw) {
  size_t i;

  if (rec == NULL || raw == NULL) {
    return SGL_E_FORMAT;
  }
  for (i = 0; raw[i] != '\0'; i++) {
    if (i + 1 >= sizeof(rec->scope)) {
      return SGL_E_LIMIT;
    }
    if (!SGL_IS_NAME_CH((unsigned char)raw[i])) {
      return SGL_E_FORMAT;
    }
  }
  memcpy(rec->scope, raw, i);
  rec->scope[i] = '\0';
  return SGL_OK;
}

int sgl_path_build(char *out, size_t out_size, const char *scope, const char *name) {
  size_t scope_len;
  size_t name_len;

  if (out == NULL || scope == NULL || name == NULL) {
    return SGL_E_FORMAT;
  }
  if (sgl_name_check(name) != SGL_OK) {
    return SGL_E_FORMAT;
  }

  scope_len = strlen(scope);
  name_len = strlen(name);
  if (scope_len + name_len + 2 > out_size) {
    return SGL_E_LIMIT;
  }

  memcpy(out, scope, scope_len);
  out[scope_len] = SGL_SEP;
  memcpy(out + scope_len + 1, name, name_len + 1);
  return SGL_OK;
}
