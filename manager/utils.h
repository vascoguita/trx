#ifndef TRX_UTILS_H
#define TRX_UTILS_H

#include <stddef.h>

void clip_sub(size_t *result, int status, size_t *left, size_t n);
char *dirname(const char *path);

#endif //TRX_UTILS_H