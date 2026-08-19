/* Flow-control credit scheduler.
 *
 * Three states: IDLE (no grant outstanding), ARMED (a grant is outstanding, nothing
 * spent from it yet), DRAINING (some of the grant has been spent). The ordinary
 * discipline is grant -> spend* -> reclaim -> grant.
 *
 * credit_grant_priority() exists for one reason: a priority frame's channel may need
 * an emergency top-up of its window credit without waiting for the normal
 * drain-then-reclaim cycle.
 */

#include "relay.h"

#include <string.h>

void credit_init(credit_sched_t *cs) {
  if (cs == NULL) {
    return;
  }
  memset(cs, 0, sizeof(*cs));
}

static void credit_record(credit_sched_t *cs, uint32_t amount) {
  cs->history[cs->history_count % CREDIT_HISTORY] = amount;
  cs->history_count++;
}

int credit_grant(credit_sched_t *cs, uint32_t amount) {
  if (cs == NULL) {
    return PL_ERR;
  }
  if (cs->state != CREDIT_IDLE) {
    return PL_ERR_STATE;
  }
  if (amount > CREDIT_MAX_GRANT) {
    return PL_ERR_LIMIT;
  }
  cs->granted = amount;
  cs->spent = 0;
  cs->state = CREDIT_ARMED;
  credit_record(cs, amount);
  return PL_OK;
}

int credit_spend(credit_sched_t *cs, uint32_t amount) {
  if (cs == NULL) {
    return PL_ERR;
  }
  if (cs->state == CREDIT_IDLE) {
    return PL_ERR_STATE;
  }
  if (amount > cs->granted - cs->spent) {
    return PL_ERR_LIMIT;
  }
  cs->spent += amount;
  cs->state = CREDIT_DRAINING;
  return PL_OK;
}

int credit_reclaim(credit_sched_t *cs) {
  if (cs == NULL) {
    return PL_ERR;
  }
  if (cs->state != CREDIT_DRAINING || cs->spent != cs->granted) {
    return PL_ERR_STATE;
  }
  cs->granted = 0;
  cs->spent = 0;
  cs->state = CREDIT_IDLE;
  return PL_OK;
}

/* Per traffic-class credit pools: bulk, normal, priority and control each get their
 * own independent grant/spend/reclaim cycle, so a class_id from the wire must be
 * bounds-checked against CREDIT_POOL_COUNT before it indexes s->pools — every
 * consumer of a wire-supplied class_id goes through this one function to do it. */
credit_sched_t *credit_pool_for(session_t *s, uint8_t class_id) {
  if (s == NULL || class_id >= CREDIT_POOL_COUNT) {
    return NULL;
  }
  return &s->pools[class_id];
}

void credit_pools_init(session_t *s) {
  size_t i;

  if (s == NULL) {
    return;
  }
  for (i = 0; i < CREDIT_POOL_COUNT; i++) {
    credit_init(&s->pools[i]);
  }
}

void credit_pools_reclaim_all(session_t *s) {
  size_t i;

  if (s == NULL) {
    return;
  }
  for (i = 0; i < CREDIT_POOL_COUNT; i++) {
    /* Best-effort: a pool that never finished draining is simply left as-is until
     * the session that owns it goes away entirely. */
    (void)credit_reclaim(&s->pools[i]);
  }
}

/* Emergency top-up for a priority frame's channel: adds to an outstanding grant
 * rather than starting a new one. */
int credit_grant_priority(credit_sched_t *cs, uint32_t amount) {
  if (cs == NULL) {
    return PL_ERR;
  }
  if (cs->state != CREDIT_DRAINING) {
    return PL_ERR_STATE;
  }
  if (amount > CREDIT_MAX_GRANT - cs->granted) {
    return PL_ERR_LIMIT;
  }
  cs->granted += amount;
  credit_record(cs, amount);
  return PL_OK;
}
