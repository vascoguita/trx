#ifndef TRX_TRX_AUTHORIZATION_H
#define TRX_TRX_AUTHORIZATION_H

#include <tee_internal_api.h>
#include "trx_authentication.h"

bool trx_authorization_authorize(trx_authentication *auth, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
bool trx_authorization_share(trx_authentication *auth, const char *mount_point, const char *R, const unsigned long int version, const char *label);
bool trx_authorization_mount(trx_authentication *auth, const char *mount_point, const char *S, const unsigned long int version, const char *label);

#endif //TRX_TRX_AUTHORIZATION_H