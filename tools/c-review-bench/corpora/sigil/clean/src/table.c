/* Interning table for field names. Slots are heap copies; a dropped slot is empty. */

#include "sgl.h"

#include <stdlib.h>
#include <string.h>

struct sgl_table {
  char **slots;
  size_t used;
  size_t cap;
};

sgl_table *sgl_table_new(void) {
  sgl_table *table = calloc(1, sizeof(*table));

  if (table == NULL) {
    return NULL;
  }
  table->cap = 4;
  table->slots = calloc(table->cap, sizeof(char *));
  if (table->slots == NULL) {
    free(table);
    return NULL;
  }
  return table;
}

void sgl_table_free(sgl_table *table) {
  size_t i;

  if (table == NULL) {
    return;
  }
  for (i = 0; i < table->used; i++) {
    free(table->slots[i]);
  }
  free(table->slots);
  free(table);
}

static int table_grow(sgl_table *table) {
  size_t cap = table->cap * 2;
  char **slots = realloc(table->slots, cap * sizeof(char *));

  if (slots == NULL) {
    return SGL_E_MEM;
  }
  memset(slots + table->cap, 0, (cap - table->cap) * sizeof(char *));
  table->slots = slots;
  table->cap = cap;
  return SGL_OK;
}

int sgl_table_intern(sgl_table *table, const char *name) {
  size_t i;
  char *copy;

  if (table == NULL || name == NULL) {
    return SGL_E_FORMAT;
  }
  for (i = 0; i < table->used; i++) {
    if (table->slots[i] != NULL && strcmp(table->slots[i], name) == 0) {
      return (int)i;
    }
  }
  if (table->used == table->cap) {
    int rc = table_grow(table);
    if (rc != SGL_OK) {
      return rc;
    }
  }

  copy = strdup(name);
  if (copy == NULL) {
    return SGL_E_MEM;
  }
  if (sgl_name_check(copy) != SGL_OK) {
    free(copy);
    return SGL_E_FORMAT;
  }

  table->slots[table->used] = copy;
  table->used++;
  return (int)(table->used - 1);
}

const char *sgl_table_name(const sgl_table *table, int slot) {
  if (table == NULL || slot < 0 || (size_t)slot >= table->used) {
    return NULL;
  }
  return table->slots[slot];
}

int sgl_table_drop(sgl_table *table, int slot) {
  if (table == NULL || slot < 0 || (size_t)slot >= table->used) {
    return SGL_E_FORMAT;
  }
  free(table->slots[slot]);
  table->slots[slot] = NULL;
  return SGL_OK;
}

size_t sgl_table_count(const sgl_table *table) {
  return table == NULL ? 0 : table->used;
}
