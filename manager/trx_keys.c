#include "trx_keys.h"
#include <stdlib.h>
#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

trx_vk *trx_vk_init(void)
{
    trx_vk *vk;
    vk = malloc(sizeof(trx_vk));
    if (TEE_AllocateTransientObject(trx_vk_type, trx_vk_bit_size, vk) != TEE_SUCCESS)
    {
        trx_vk_clear(vk);
        return NULL;
    }
    return vk;
}

TEE_Result trx_vk_gen(trx_vk *vk)
{
    return TEE_GenerateKey(*vk, trx_vk_bit_size, NULL, 0);
}

void trx_vk_clear(trx_vk *vk)
{
    if (vk)
    {
        TEE_FreeTransientObject(*vk);
        free(vk);
    }
}

TEE_Result trx_vk_from_bytes(trx_vk *vk, uint8_t *buffer, uint32_t buffer_size)
{
    TEE_Attribute attr = {};
    TEE_Result res;

    if (!buffer || (buffer_size != trx_vk_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
    res = TEE_PopulateTransientObject(*vk, &attr, 1);

out:
    return res;
}

TEE_Result trx_vk_to_bytes(trx_vk *vk, uint8_t *buffer, uint32_t *buffer_size)
{
    return TEE_GetObjectBufferAttribute(*vk, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
}

trx_dek *trx_dek_init(void)
{
    trx_dek *dek;
    dek = malloc(sizeof(trx_dek));
    if (TEE_AllocateTransientObject(trx_dek_type, trx_dek_bit_size, dek) != TEE_SUCCESS)
    {
        trx_dek_clear(dek);
        return NULL;
    }
    return dek;
}

TEE_Result trx_dek_gen(trx_dek *dek)
{
    return TEE_GenerateKey(*dek, trx_dek_bit_size, NULL, 0);
}

void trx_dek_clear(trx_dek *dek)
{
    if (dek)
    {
        TEE_FreeTransientObject(*dek);
        free(dek);
    }
}

TEE_Result trx_dek_from_bytes(trx_dek *dek, uint8_t *buffer, uint32_t buffer_size)
{
    TEE_Attribute attr = {};
    TEE_Result res;

    if (!buffer || (buffer_size != trx_dek_size))
    {
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
    res = TEE_PopulateTransientObject(*dek, &attr, 1);

out:
    return res;
}

TEE_Result trx_dek_to_bytes(trx_dek *dek, uint8_t *buffer, uint32_t *buffer_size)
{
    return TEE_GetObjectBufferAttribute(*dek, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
}

trx_tsk *trx_tsk_init(void)
{
    trx_tsk *tsk;
    tsk = malloc(sizeof(trx_tsk));
    if (TEE_AllocateTransientObject(trx_tsk_type, trx_tsk_bit_size, tsk) != TEE_SUCCESS)
    {
        trx_tsk_clear(tsk);
        return NULL;
    }
    return tsk;
}

TEE_Result trx_tsk_derive(trx_tsk *tsk, trx_vk *vk, TEE_UUID *uuid)
{
    TEE_Result res;
    TEE_OperationHandle op_handle;
    uint8_t tsk_buffer[trx_tsk_size];
    uint32_t tsk_buffer_size = trx_tsk_size;
    TEE_Attribute attr = {};

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, trx_vk_bit_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    res = TEE_SetOperationKey(op_handle, *vk);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_MACInit(op_handle, NULL, 0);
    res = TEE_MACComputeFinal(op_handle, uuid, sizeof(TEE_UUID), tsk_buffer, &tsk_buffer_size);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, tsk_buffer, tsk_buffer_size);
    res = TEE_PopulateTransientObject(*tsk, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        goto out;
    }

out:
    TEE_FreeOperation(op_handle);
    return res;
}

void trx_tsk_clear(trx_tsk *tsk)
{
    if (tsk)
    {
        TEE_FreeTransientObject(*tsk);
        free(tsk);
    }
}