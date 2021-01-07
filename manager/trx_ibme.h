#ifndef TRX_TRX_IBME_H
#define TRX_TRX_IBME_H

#include <tee_internal_api.h>
#include <ibme/ibme.h>

typedef struct _trx_ibme
{
    char *param_str;
    size_t param_str_size;
    pairing_t *pairing;
    MPK *mpk;
    EK *ek;
    DK *dk;
} trx_ibme;

trx_ibme *trx_ibme_init(void);
void trx_ibme_clear(trx_ibme *ibme);
trx_ibme *trx_ibme_create(char *param_str, size_t param_str_size, char *mpk_str, size_t mpk_str_size,
                          char *ek_str, size_t ek_str_size, char *dk_str, size_t dk_str_size);
TEE_Result trx_ibme_set_param_str(trx_ibme *ibme, char *param_str, size_t param_str_size);
TEE_Result trx_ibme_set_mpk(trx_ibme *ibme, char *mpk_str, size_t mpk_str_size);
TEE_Result trx_ibme_set_dk(trx_ibme *ibme, char *dk_str, size_t dk_str_size);
TEE_Result trx_ibme_set_ek(trx_ibme *ibme, char *ek_str, size_t ek_str_size);

int trx_ibme_snprint(char *s, size_t n, trx_ibme *ibme);
int trx_ibme_set_str(char *s, size_t n, trx_ibme *ibme);

TEE_Result trx_ibme_save(trx_ibme *ibme);
TEE_Result trx_ibme_load(trx_ibme *ibme);

static const char trx_ibme_id[] = "trx_ibme";

#endif //TRX_TRX_IBME_H
