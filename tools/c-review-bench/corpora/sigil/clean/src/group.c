/* Nested group walk. Each entry is kind(1) sublen(2) followed by sublen bytes. */

#include "sgl.h"

int sgl_group_walk(const unsigned char *p, size_t len, int depth, int *leaves) {
  size_t off = 0;

  if (p == NULL || leaves == NULL) {
    return SGL_E_FORMAT;
  }
  if (depth > SGL_GROUP_DEPTH_MAX) {
    return SGL_E_LIMIT;
  }

  while (off + 3 <= len) {
    unsigned char kind = p[off];
    size_t sub = (size_t)(((size_t)p[off + 1] << 8) | (size_t)p[off + 2]);

    off += 3;
    if (sub > len - off) {
      return SGL_E_FORMAT;
    }
    if (kind == SGL_KIND_GROUP) {
      int rc = sgl_group_walk(p + off, sub, depth + 1, leaves);
      if (rc != SGL_OK) {
        return rc;
      }
    } else {
      *leaves += 1;
    }
    off += sub;
  }
  return SGL_OK;
}
