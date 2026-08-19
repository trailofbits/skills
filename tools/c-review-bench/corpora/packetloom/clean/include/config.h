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

/* Retransmit timer wheel (timer.c). */
#define TIMER_BUCKETS 16
#define TIMER_MAX_ARMED 4

/* Flow-control credit scheduler (credit.c). */
#define CREDIT_MAX_GRANT 4096
#define CREDIT_HISTORY 4
#define CREDIT_POOL_COUNT 4 /* bulk, normal, priority, control */

/* Config/option parser (optparse.c). Depth counts brace nesting, not bytes. */
#define OPT_MAX_DEPTH 4
#define OPT_MAX_LEN 64

/* Telemetry counters (stats.c). */
#define STATS_MAX_COUNTERS 12

/* Out-of-order fragment cache, the second reassembly strategy (reasm_oo.c). Each
 * slot holds one fragment's worth of the fast-path payload. */
#define REASM_OO_SLOTS 8
#define OO_SLOT_CAP (FRAME_MAX / MAX_FRAGMENTS)

#endif /* PL_CONFIG_H */
