#include <tee_internal_api.h>
#include <stdlib.h>
#include <string.h>
#include "trx_keys.h"
#include "trx_cipher.h"

TEE_Result trx_cipher_encrypt_data(trx_dek *dek, void *data, size_t data_size, unsigned long int version,
                                     void *id, size_t id_size, void *dst, size_t *dst_size)
{
    TEE_Result res;
    uint8_t *nonce, *tag, *data_enc;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint32_t tmp_data_enc_size, tmp_tag_size;
    size_t exp_dst_size;

    exp_dst_size = nonce_size + tag_size + data_size;

    if (!dst)
    {
        *dst_size = exp_dst_size;
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    if (*dst_size != exp_dst_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    nonce = dst;
    tag = nonce + nonce_size;
    data_enc = tag + tag_size;

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, trx_dek_bit_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_SetOperationKey(op_handle, *dek);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_GenerateRandom(nonce, nonce_size);
    res = TEE_AEInit(op_handle, nonce, nonce_size, tag_bit_size, 0, 0);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_AEUpdateAAD(op_handle, &version, version_size);
    TEE_AEUpdateAAD(op_handle, id, id_size);

    tmp_data_enc_size = data_size;
    tmp_tag_size = tag_size;
    res = TEE_AEEncryptFinal(op_handle, data, data_size, data_enc, &tmp_data_enc_size, tag, &tmp_tag_size);
    if ((res != TEE_SUCCESS) || (tmp_data_enc_size != data_size) || (tmp_tag_size != tag_size))
    {
        res = TEE_ERROR_GENERIC;
    }

out:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    return res;
}

TEE_Result trx_cipher_decrypt_data(trx_dek *dek, void *src, size_t src_size, unsigned long int version,
                                   void *id, size_t id_size, void *dst, size_t *dst_size)
{
    TEE_Result res;
    uint8_t *nonce, *tag, *data_enc;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint32_t exp_dst_size, min_src_size;

    (void)&id;
    (void)&id_size;

    min_src_size = tag_size + nonce_size;
    if (src_size < min_src_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    nonce = src;
    tag = nonce + nonce_size;
    data_enc = tag + tag_size;

    exp_dst_size = src_size - min_src_size;
    if (!dst)
    {
        *dst_size = exp_dst_size;
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    if (*dst_size != exp_dst_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, trx_dek_bit_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_SetOperationKey(op_handle, *dek);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_AEInit(op_handle, nonce, nonce_size, tag_bit_size, 0, 0);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_AEUpdateAAD(op_handle, &version, version_size);
    TEE_AEUpdateAAD(op_handle, id, id_size);

    res = TEE_AEDecryptFinal(op_handle, data_enc, exp_dst_size, dst, &exp_dst_size, tag, tag_size);
    if ((res != TEE_SUCCESS) || (exp_dst_size != *dst_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    return res;
}

TEE_Result trx_cipher_encrypt_dek(trx_tsk *tsk, trx_dek *dek, void *dst, size_t *dst_size)
{
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint8_t dek_buffer[trx_dek_size], *iv, *dek_enc;
    uint32_t exp_dst_size, tmp_size;

    exp_dst_size = iv_size + trx_dek_size;
    if (!dst)
    {
        *dst_size = exp_dst_size;
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    if (*dst_size != exp_dst_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    iv = dst;
    dek_enc = iv + iv_size;

    tmp_size = trx_dek_size;
    res = trx_dek_to_bytes(dek, dek_buffer, &tmp_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_GenerateRandom(iv, iv_size);

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, trx_tsk_bit_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_SetOperationKey(op_handle, *tsk);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_CipherInit(op_handle, iv, iv_size);

    tmp_size = trx_dek_size;
    res = TEE_CipherDoFinal(op_handle, dek_buffer, trx_dek_size, dek_enc, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != trx_dek_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    return res;
}

TEE_Result trx_cipher_decrypt_dek(trx_tsk *tsk, void *src, size_t src_size, trx_dek *dek)
{
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint8_t dek_buffer[trx_dek_size], *iv, *dek_enc;
    uint32_t tmp_size;

    if (src_size != (iv_size + trx_dek_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    iv = src;
    dek_enc = iv + iv_size;

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, trx_tsk_bit_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_SetOperationKey(op_handle, *tsk);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_CipherInit(op_handle, iv, iv_size);

    tmp_size = trx_dek_size;
    res = TEE_CipherDoFinal(op_handle, dek_enc, trx_dek_size, dek_buffer, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != trx_dek_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_dek_from_bytes(dek, dek_buffer, trx_dek_size);

out:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    return res;
}

TEE_Result trx_cipher_encrypt(trx_vk *vk, TEE_UUID *uuid, void *src, size_t src_size,
                              unsigned long int version, void *id, size_t id_size,
                              void *dst, size_t *dst_size)
{
    TEE_Result res;
    trx_tsk *tsk = NULL;
    trx_dek *dek = NULL;
    uint8_t *data_enc, *dek_enc;
    size_t data_enc_size, dek_enc_size, exp_dst_size;

    res = trx_cipher_encrypt_data(NULL, src, src_size, version, id, id_size, NULL, &data_enc_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_cipher_encrypt_dek(NULL, NULL, NULL, &dek_enc_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    exp_dst_size = data_enc_size + dek_enc_size;
    if (!dst)
    {
        *dst_size = exp_dst_size;
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    if (*dst_size != exp_dst_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    dek_enc = dst;
    data_enc = dek_enc + dek_enc_size;

    if (!(dek = trx_dek_init()))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_dek_gen(dek);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = trx_cipher_encrypt_data(dek, src, src_size, version, id, id_size, data_enc, &data_enc_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }
    if (!(tsk = trx_tsk_init()))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_tsk_derive(tsk, vk, uuid);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = trx_cipher_encrypt_dek(tsk, dek, dek_enc, &dek_enc_size);
    if (res != TEE_SUCCESS)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    trx_tsk_clear(tsk);
    trx_dek_clear(dek);
    return res;
}

TEE_Result trx_cipher_decrypt(trx_vk *vk, TEE_UUID *uuid, void *src, size_t src_size,
                              unsigned long int version, void *id, size_t id_size,
                              void *dst, size_t *dst_size)
{
    TEE_Result res;
    trx_dek *dek = NULL;
    trx_tsk *tsk = NULL;
    uint8_t *data_enc, *dek_enc;
    size_t data_enc_size, dek_enc_size, exp_dst_size;

    res = trx_cipher_encrypt_dek(NULL, NULL, NULL, &dek_enc_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_cipher_encrypt_data(NULL, NULL, 0, 0, NULL, 0, NULL, &data_enc_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (src_size < (dek_enc_size + data_enc_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    dek_enc = src;
    data_enc = dek_enc + dek_enc_size;

    data_enc_size = src_size - dek_enc_size;

    res = trx_cipher_decrypt_data(NULL, data_enc, data_enc_size, version,  id, id_size, NULL, &exp_dst_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!dst)
    {
        *dst_size = exp_dst_size;
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    if (*dst_size != exp_dst_size)
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(tsk = trx_tsk_init()))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_tsk_derive(tsk, vk, uuid);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    if (!(dek = trx_dek_init()))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_cipher_decrypt_dek(tsk, dek_enc, dek_enc_size, dek);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = trx_cipher_decrypt_data(dek, data_enc, data_enc_size, version, id, id_size, dst, &exp_dst_size);
    if ((res != TEE_SUCCESS) || (exp_dst_size != *dst_size))
    {
        res = TEE_ERROR_GENERIC;
    }

out:
    trx_dek_clear(dek);
    trx_tsk_clear(tsk);
    return res;
}