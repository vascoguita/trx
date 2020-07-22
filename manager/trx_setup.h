#ifndef TRX_TRX_SETUP_H
#define TRX_TRX_SETUP_H

#include <tee_internal_api.h>

#define setup_pobj_id "setup"

typedef struct _trx_setup {
    char *path;
    size_t path_size;
} trx_setup;

int trx_setup_init(trx_setup **setup);
void trx_setup_clear(trx_setup *setup);
int trx_setup_snprint(char *s, size_t n, trx_setup *setup);
int trx_setup_set_str(char *s, size_t n, trx_setup *setup);

TEE_Result trx_setup_save(trx_setup *setup);

#endif //TRX_TRX_SETUP_H