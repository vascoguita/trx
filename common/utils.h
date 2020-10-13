#ifndef TRX_UTILS_H
#define TRX_UTILS_H

#include <stddef.h>

#define PATH_MAX 1024

void clip_sub(size_t *result, int status, size_t *left, size_t n);
char *basename(const char *path);
char *dirname(const char *path);
int tee_uuid_snprint(char *s, size_t n, TEE_UUID *uuid);

int pad(const uint8_t *data, size_t data_size, uint8_t bs, uint8_t *p, size_t *p_size);
int unpad(const uint8_t *p, size_t p_size, uint8_t bs, uint8_t *data, size_t *data_size);

#endif //TRX_UTILS_H