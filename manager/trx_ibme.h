#ifndef TRX_TRX_IBME_H
#define TRX_TRX_IBME_H

#include <tee_internal_api.h>
#include "trx_manager_defaults.h"
#include <ibme/ibme.h>

typedef struct _trx_ibme {
    char *param_str;
    size_t param_str_size;
    MPK *mpk;
    EK *ek;
    DK *dk;
} trx_ibme;

trx_ibme *trx_ibme_init(void);
void trx_ibme_clear(trx_ibme *ibme);
int trx_ibme_snprint(char *s, size_t n, trx_ibme *ibme);
int trx_ibme_set_str(char *s, size_t n, trx_ibme *ibme);

TEE_Result trx_ibme_save(trx_ibme *ibme);
TEE_Result trx_ibme_load(trx_ibme *ibme);

#endif //TRX_TRX_IBME_H
