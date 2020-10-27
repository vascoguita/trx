#ifndef TRX_TRX_FILE_H
#define TRX_TRX_FILE_H

#include <tee_internal_api.h>
#include "trx_pobj.h"
#include <ibme/cipher.h>

struct _trx_pobj;

typedef struct _trx_file {
    char *ree_path;
    size_t ree_path_size;
    Cipher *enc_bk;
    void *fek_enc_iv;
    size_t fek_enc_iv_size;
    void *fek_enc;
    size_t fek_enc_size;
    void *data_enc_iv;
    size_t data_enc_iv_size;
    void *data_enc;
    size_t data_enc_size;
} trx_file;

trx_file *trx_file_init(const char *ree_path, size_t ree_path_size);
void trx_file_clear(trx_file *file);
int trx_file_save(trx_file *file);
int trx_file_load(trx_file *file);

int trx_file_serialize(trx_file *file, void *data, size_t *data_size);
int trx_file_deserialize(trx_file *file, void *data, size_t data_size);

TEE_Result trx_file_encrypt(trx_file *file, struct _trx_pobj *pobj);
TEE_Result trx_file_decrypt(trx_file *file, struct _trx_pobj *pobj);

#endif //TRX_TRX_FILE_H
