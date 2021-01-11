#ifndef TRX_UTILS_H
#define TRX_UTILS_H

#include <stddef.h>
#include <tee_internal_api.h>

char *basename(const char *path);
char *dirname(const char *path);
char *path(const char *dirname, const char *basename);

#endif //TRX_UTILS_H