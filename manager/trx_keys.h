#ifndef TRX_TRX_KEYS_H
#define TRX_TRX_KEYS_H

#include <tee_internal_api.h>

typedef TEE_ObjectHandle trx_bk, trx_dek, trx_tsk;

static const uint32_t trx_bk_type = TEE_TYPE_HMAC_SHA256;
static const uint32_t trx_bk_size = 32;
static const uint32_t trx_bk_bit_size = trx_bk_size * 8;
static const char trx_bk_ree_basename[] = "trx_bk.trx";

static const uint32_t trx_dek_type = TEE_TYPE_AES;
static const uint32_t trx_dek_size = 32;
static const uint32_t trx_dek_bit_size = trx_dek_size * 8;

static const uint32_t trx_tsk_type = TEE_TYPE_AES;
static const uint32_t trx_tsk_size = 32;
static const uint32_t trx_tsk_bit_size = trx_tsk_size * 8;

trx_bk *trx_bk_init(void);
TEE_Result trx_bk_gen(trx_bk *bk);
void trx_bk_clear(trx_bk *bk);
TEE_Result trx_bk_from_bytes(trx_bk *bk, uint8_t *buffer, uint32_t buffer_size);
TEE_Result trx_bk_to_bytes(trx_bk *bk, uint8_t *buffer, uint32_t *buffer_size);

trx_dek *trx_dek_init(void);
TEE_Result trx_dek_gen(trx_dek *dek);
void trx_dek_clear(trx_dek *dek);
TEE_Result trx_dek_from_bytes(trx_dek *dek, uint8_t *buffer, uint32_t buffer_size);
TEE_Result trx_dek_to_bytes(trx_dek *dek, uint8_t *buffer, uint32_t *buffer_size);

trx_tsk *trx_tsk_init(void);
TEE_Result trx_tsk_derive(trx_tsk *tsk, trx_bk *bk, TEE_UUID *uuid);
void trx_tsk_clear(trx_tsk *tsk);

#endif //TRX_TRX_KEYS_H