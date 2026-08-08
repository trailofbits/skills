#ifndef PL_CONFIG_H
#define PL_CONFIG_H

/* Build-time limits. These are the numbers the wire format and the tables agree on;
 * changing one without auditing every place it is encoded is how ids start aliasing. */

#define MAX_CHANNELS 128 /* raised from 64 when the multiplexer grew a second bank */
#define MAX_WINDOW 32
#define MAX_FRAGMENTS 16
#define MAX_RETRIES 10
#define MAX_CODECS 8
#define MAX_SESSIONS 16

#define FRAME_MAX 4096
#define HEADER_LEN 8   /* magic(2) version(1) priority(1) total_len(4) */
#define FRAG_HDR_LEN 8 /* chan(2) index(1) count(1) priority(1) pad(3) */

#define LABEL_MAX 16
#define NAME_MAX_LEN 32
#define SCRATCH_MAX 256
#define ARENA_SLOTS 64

#endif /* PL_CONFIG_H */
