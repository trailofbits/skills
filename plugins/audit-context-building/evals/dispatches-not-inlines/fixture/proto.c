#include <string.h>

#include "proto.h"

static int decode_length(const struct header *h, size_t *out_len)
{
    if (h->flags & FLAG_EXTENDED) {
        *out_len = ((size_t)(h->flags >> 4) << 16) | h->payload_len;
        return 0;
    }

    if (h->payload_len > MAX_PAYLOAD)
        return -1;

    *out_len = h->payload_len;
    return 0;
}

int validate_header(const uint8_t *buf, size_t buf_len, size_t *out_len)
{
    struct header h;

    if (buf_len < HEADER_LEN)
        return -1;

    h.version     = buf[0];
    h.flags       = buf[1];
    h.payload_len = (uint16_t)((buf[2] << 8) | buf[3]);

    if (h.version != PROTO_VERSION)
        return -1;

    return decode_length(&h, out_len);
}

int parse_record(const uint8_t *buf, size_t buf_len, uint8_t *dst)
{
    size_t payload_len;

    if (validate_header(buf, buf_len, &payload_len) != 0)
        return -1;

    memcpy(dst, buf + HEADER_LEN, payload_len);
    return 0;
}
