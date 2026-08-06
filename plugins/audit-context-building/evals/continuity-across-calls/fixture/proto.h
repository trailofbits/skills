#ifndef PROTO_H
#define PROTO_H

#include <stddef.h>
#include <stdint.h>

#define PROTO_VERSION  2
#define MAX_PAYLOAD    256
#define HEADER_LEN     4

/* Frame flags, header byte 1. The high nibble is reserved for extended
 * frames; the low nibble holds the flags below. */
#define FLAG_COMPRESSED  0x01
#define FLAG_EXTENDED    0x02

struct header {
    uint8_t  version;
    uint8_t  flags;
    uint16_t payload_len;
};

/*
 * Validates a frame header.
 *
 * Returns 0 on success, -1 on failure. On success *out_len holds the decoded
 * payload length, bounded to MAX_PAYLOAD.
 */
int validate_header(const uint8_t *buf, size_t buf_len, size_t *out_len);

/*
 * Copies one record's payload out of buf into dst.
 * dst must have room for MAX_PAYLOAD bytes.
 */
int parse_record(const uint8_t *buf, size_t buf_len, uint8_t *dst);

#endif /* PROTO_H */
