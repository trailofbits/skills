#include <stdlib.h>
#include <string.h>

#include "proto.h"

struct frame {
    uint8_t  payload[MAX_PAYLOAD];
    size_t   len;
    uint32_t seq;
};

static struct frame *g_pending[16];
static unsigned      g_pending_count;

int frame_ingest(const uint8_t *buf, size_t buf_len, uint32_t seq)
{
    struct frame *f;

    if (g_pending_count >= 16)
        return -1;

    f = calloc(1, sizeof(*f));
    if (!f)
        return -1;

    if (parse_record(buf, buf_len, f->payload) != 0) {
        free(f);
        return -1;
    }

    f->seq = seq;
    g_pending[g_pending_count++] = f;
    return 0;
}

struct frame *frame_take(uint32_t seq)
{
    unsigned i;

    for (i = 0; i < g_pending_count; i++) {
        if (g_pending[i]->seq == seq) {
            struct frame *f = g_pending[i];
            g_pending[i] = g_pending[--g_pending_count];
            return f;
        }
    }

    return NULL;
}

void frame_flush(void)
{
    unsigned i;

    for (i = 0; i < g_pending_count; i++)
        free(g_pending[i]);

    g_pending_count = 0;
}
