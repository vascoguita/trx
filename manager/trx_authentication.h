#ifndef TRX_TRX_AUTHENTICATION_H
#define TRX_TRX_AUTHENTICATION_H

#include <tee_internal_api.h>

typedef struct _trx_authentication
{
    char *pin;
    size_t pin_size;
} trx_authentication;

trx_authentication *trx_authentication_init(void);
void trx_authentication_clear(trx_authentication *auth);
TEE_Result trx_authentication_save(trx_authentication *auth);
TEE_Result trx_authentication_load(trx_authentication *auth);
TEE_Result trx_authentication_setup(trx_authentication *auth);
bool trx_authentication_check(trx_authentication *auth, char *input);

static const char trx_authentication_id[] = "trx_authentication";

#endif //TRX_TRX_AUTHENTICATION_H