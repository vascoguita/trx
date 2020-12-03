#ifndef TRX_TRX_FILE_H
#define TRX_TRX_FILE_H

#include <tee_internal_api.h>
#include "trx_pobj.h"
#include "trx_manager_defaults.h"

struct _trx_pobj;

typedef struct _trx_file
{
    char *ree_basename;
    size_t ree_basename_size;
    char *bk_enc;
    size_t bk_enc_size;
    uint8_t fek_enc_iv[IV_SIZE];
    void *fek_enc;
    size_t fek_enc_size;
    uint8_t data_enc_nonce[NONCE_SIZE];
    void *data_enc;
    size_t data_enc_size;
    unsigned long int version;
    uint8_t tag[TAG_SIZE];
    struct _trx_pobj *pobj;
} trx_file;

trx_file *trx_file_init(void);
void trx_file_clear(trx_file *file);
int trx_file_save(trx_file *file);
int trx_file_load(trx_file *file);

int trx_file_serialize(trx_file *file, void *data, size_t *data_size);
int trx_file_deserialize(trx_file *file, void *data, size_t data_size);

TEE_Result trx_file_encrypt(trx_file *file);
TEE_Result trx_file_decrypt(trx_file *file);

#endif //TRX_TRX_FILE_H
