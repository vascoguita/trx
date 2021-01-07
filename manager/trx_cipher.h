#ifndef TRX_TRX_CIPHER_H
#define TRX_TRX_CIPHER_H

#include <tee_internal_api.h>

TEE_Result trx_cipher_encrypt_data(trx_dek *dek, void *data, size_t data_size, unsigned long int new_version,
                                   void *dst, size_t *dst_size);
TEE_Result trx_cipher_decrypt_data(trx_dek *dek, void *src, size_t src_size, unsigned long int *last_version,
                                   void *dst, size_t *dst_size);
TEE_Result trx_cipher_encrypt_dek(trx_tsk *tsk, trx_dek *dek, void *dst, size_t *dst_size);
TEE_Result trx_cipher_decrypt_dek(trx_tsk *tsk, void *src, size_t src_size, trx_dek *dek);
TEE_Result trx_cipher_encrypt(trx_vk *vk, TEE_UUID *uuid, void *src, size_t src_size,
                              unsigned long int new_version, void *dst, size_t *dst_size);
TEE_Result trx_cipher_decrypt(trx_vk *vk, TEE_UUID *uuid, void *src, size_t src_size,
                              unsigned long int *last_version, void *dst, size_t *dst_size);

static const uint32_t version_size = sizeof(unsigned long int);
static const uint32_t nonce_size = 12;
static const uint32_t tag_size = 16;
static const uint32_t tag_bit_size = tag_size * 8;
static const uint32_t iv_size = 16;

#endif //TRX_TRX_CIPHER_H