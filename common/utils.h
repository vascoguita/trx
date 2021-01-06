#ifndef TRX_UTILS_H
#define TRX_UTILS_H

#include <stddef.h>
#include <tee_internal_api.h>

#define PATH_MAX 1024

void clip_sub(size_t *result, int status, size_t *left, size_t n);
char *basename(const char *path);
char *dirname(const char *path);
char *path(const char *dirname, const char *basename);
int tee_uuid_snprint(char *s, size_t n, TEE_UUID *uuid);

#endif //TRX_UTILS_H