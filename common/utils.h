#ifndef TRX_UTILS_H
#define TRX_UTILS_H

#include <stddef.h>

#define PATH_MAX 1024

void clip_sub(size_t *result, int status, size_t *left, size_t n);
char *basename(const char *path);
char *dirname(const char *path);
int tee_uuid_snprint(char *s, size_t n, TEE_UUID *uuid);

#endif //TRX_UTILS_H