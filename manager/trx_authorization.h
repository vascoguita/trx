#ifndef TRX_TRX_AUTHORIZATION_H
#define TRX_TRX_AUTHORIZATION_H

#include <tee_internal_api.h>

bool trx_authorization_authorize(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
bool trx_authorization_share(const char *mount_point, const char *R, const unsigned long int version, const char *label);
bool trx_authorization_mount(const char *mount_point, const char *S, const unsigned long int version, const char *label);

#endif //TRX_TRX_AUTHORIZATION_H