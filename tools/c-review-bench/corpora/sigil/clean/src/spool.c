/* Spooling a decoded record to disk. The spool file must not already exist. */

#include "sgl.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int sgl_spool_write(const char *path, const sgl_record *rec) {
  size_t i;
  int fd;

  if (path == NULL || rec == NULL) {
    return SGL_E_FORMAT;
  }

  /* O_EXCL keeps the existence test and the create in one step. */
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    return SGL_E_IO;
  }

  for (i = 0; i < rec->field_count; i++) {
    const sgl_field *field = &rec->fields[i];
    char line[SGL_PATH_MAX];
    int n;

    n = snprintf(line, sizeof(line), "%s/%s=%.*s\n", rec->scope, field->name,
                 (int)field->value_len, (const char *)field->value);
    if (n < 0 || (size_t)n >= sizeof(line)) {
      close(fd);
      return SGL_E_LIMIT;
    }
    if (write(fd, line, (size_t)n) != (ssize_t)n) {
      close(fd);
      return SGL_E_IO;
    }
  }

  close(fd);
  return SGL_OK;
}
