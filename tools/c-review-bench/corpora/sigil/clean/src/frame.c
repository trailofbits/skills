/* Frame header decoding. Every byte here comes off the wire. */

#include "sgl.h"

#include <string.h>

static uint16_t rd16(const unsigned char *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

size_t sgl_frame_span(const sgl_frame *frame) {
  return (size_t)SGL_HEADER_LEN + (size_t)frame->payload_len + (size_t)SGL_TAG_LEN;
}

int sgl_frame_parse(const unsigned char *buf, size_t len, sgl_frame *out) {
  size_t need;

  if (buf == NULL || out == NULL) {
    return SGL_E_FORMAT;
  }
  if (len < SGL_HEADER_LEN) {
    return SGL_E_SHORT;
  }
  if (buf[0] != SGL_MAGIC0 || buf[1] != SGL_MAGIC1) {
    return SGL_E_FORMAT;
  }
  if (buf[2] != SGL_VERSION) {
    return SGL_E_FORMAT;
  }

  memset(out, 0, sizeof(*out));
  out->version = buf[2];
  out->flags = buf[3];
  out->seq = rd32(buf + 4);
  out->payload_len = rd16(buf + 8);

  if (out->payload_len > SGL_MAX_PAYLOAD) {
    return SGL_E_LIMIT;
  }

  need = sgl_frame_span(out);
  if (len < need) {
    return SGL_E_SHORT;
  }

  out->payload = buf + SGL_HEADER_LEN;
  out->tag = buf + SGL_HEADER_LEN + out->payload_len;
  return SGL_OK;
}
