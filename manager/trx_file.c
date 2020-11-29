#include "trx_file.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <ree_fs_api.h>
#include <utee_defines.h>
#include <ibme/padding.h>
#include "trx_pobj.h"

trx_file *trx_file_init(void)
{
    trx_file *file;
    if ((file = (struct _trx_file *)malloc(sizeof(struct _trx_file))) == NULL)
    {
        return NULL;
    }
    file->ree_basename = NULL;
    file->ree_basename_size = 0;
    file->bk_enc = NULL;
    file->bk_enc_size = 0;
    file->fek_enc = NULL;
    file->fek_enc_size = 0;
    file->data_enc = NULL;
    file->data_enc_size = 0;
    file->pobj = NULL;
    return file;
}

void trx_file_clear(trx_file *file)
{
    if (file)
    {
        free(file->ree_basename);
        free(file->bk_enc);
        free(file->fek_enc);
        free(file->data_enc);
    }
    free(file);
}

int trx_file_save(trx_file *file)
{
    int fd;
    TEE_Result res;
    void *data;
    size_t data_size;
    char *ree_path;
    size_t ree_path_size;

    data_size = 0;
    if (trx_file_serialize(file, NULL, &data_size) != 0)
    {
        return 1;
    }
    if (!(data = malloc(data_size)))
    {
        return 1;
    }
    if (trx_file_serialize(file, data, &data_size) != 0)
    {
        free(data);
        return 1;
    }

    if ((ree_path_size = snprintf(NULL, 0, "%s/%s", file->pobj->tss->db->ree_dirname, file->ree_basename) + 1) < 1)
    {
        free(data);
        return 1;
    }
    if (!(ree_path = malloc(ree_path_size)))
    {
        free(data);
        return 1;
    }
    if (ree_path_size != ((size_t)snprintf(ree_path, ree_path_size, "%s/%s", file->pobj->tss->db->ree_dirname, file->ree_basename) + 1))
    {
        free(data);
        free(ree_path);
        return 1;
    }

    res = ree_fs_api_create(ree_path, ree_path_size, &fd);
    if (res != TEE_SUCCESS)
    {
        free(data);
        free(ree_path);
        return 1;
    }
    free(ree_path);
    res = ree_fs_api_write(fd, 0, &data_size, sizeof(size_t));
    if (res != TEE_SUCCESS)
    {
        free(data);
        ree_fs_api_close(fd);
        return 1;
    }
    res = ree_fs_api_write(fd, sizeof(size_t), data, data_size);
    if (res != TEE_SUCCESS)
    {
        free(data);
        ree_fs_api_close(fd);
        return 1;
    }
    free(data);
    ree_fs_api_close(fd);
    return 0;
}

int trx_file_load(trx_file *file)
{
    int fd;
    TEE_Result res;
    size_t tmp_size;
    void *data;
    size_t data_size;
    char *ree_path;
    size_t ree_path_size;

    if ((ree_path_size = snprintf(NULL, 0, "%s/%s", file->pobj->tss->db->ree_dirname, file->ree_basename) + 1) < 1)
    {
        return 1;
    }
    if (!(ree_path = malloc(ree_path_size)))
    {
        return 1;
    }
    if (ree_path_size != ((size_t)snprintf(ree_path, ree_path_size, "%s/%s", file->pobj->tss->db->ree_dirname, file->ree_basename) + 1))
    {
        free(ree_path);
        return 1;
    }

    res = ree_fs_api_open(ree_path, ree_path_size, &fd);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }
    free(ree_path);
    tmp_size = sizeof(size_t);
    res = ree_fs_api_read(fd, 0, &data_size, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != sizeof(size_t)))
    {
        ree_fs_api_close(fd);
        return 1;
    }

    if (!(data = malloc(data_size)))
    {
        ree_fs_api_close(fd);
        return 1;
    }

    tmp_size = data_size;
    res = ree_fs_api_read(fd, sizeof(size_t), data, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != data_size))
    {
        ree_fs_api_close(fd);
        return 1;
    }
    ree_fs_api_close(fd);

    if (trx_file_deserialize(file, data, data_size) != 0)
    {
        free(data);
        return 1;
    }
    free(data);
    return 0;
}

TEE_Result trx_file_encrypt(trx_file *file)
{
    TEE_Result res;
    TEE_OperationHandle op_handle;
    uint32_t tmp_data_enc_size, tmp_tag_size, tmp_fek_enc_size;
    TEE_ObjectHandle fek, tsk;
    uint8_t fek_buffer[AES_KEY_SIZE];
    uint32_t fek_buffer_size;
    uint8_t tsk_buffer[HMACSHA256_TAG_SIZE];
    uint32_t tsk_buffer_size;
    TEE_Attribute attr = {};

    fek_buffer_size = AES_KEY_SIZE;
    tsk_buffer_size = HMACSHA256_TAG_SIZE;

    file->data_enc_size = 0;
    if (pad(file->pobj->data, file->pobj->data_size, TEE_AES_BLOCK_SIZE, NULL, &file->data_enc_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }

    if (!(file->data_enc = malloc(file->data_enc_size)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (pad(file->pobj->data, file->pobj->data_size, TEE_AES_BLOCK_SIZE, file->data_enc, &file->data_enc_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }

    TEE_GenerateRandom(file->data_enc_nonce, NONCE_SIZE);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BIT_SIZE, &fek);
    if (res != TEE_SUCCESS)
    {
        return res;
    }

    res = TEE_GenerateKey(fek, AES_KEY_BIT_SIZE, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(fek);
        return res;
    }

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, AES_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(fek);
        return res;
    }
    res = TEE_SetOperationKey(op_handle, fek);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return res;
    }

    res = TEE_AEInit(op_handle, file->data_enc_nonce, NONCE_SIZE, TAG_BIT_SIZE, 0, file->data_enc_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return res;
    }
    tmp_data_enc_size = file->data_enc_size;
    tmp_tag_size = TAG_SIZE;
    res = TEE_AEEncryptFinal(op_handle, file->data_enc, file->data_enc_size, file->data_enc, &tmp_data_enc_size, file->tag, &tmp_tag_size);
    if ((res != TEE_SUCCESS) || (tmp_data_enc_size != file->data_enc_size) || (tmp_tag_size != TAG_SIZE))
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return TEE_ERROR_GENERIC;
    }
    TEE_FreeOperation(op_handle);
    res = TEE_GetObjectBufferAttribute(fek, TEE_ATTR_SECRET_VALUE, fek_buffer, &fek_buffer_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(fek);
        return res;
    }

    TEE_FreeTransientObject(fek);
    file->fek_enc_size = 0;

    if (pad(fek_buffer, fek_buffer_size, TEE_AES_BLOCK_SIZE, NULL, &file->fek_enc_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }

    if (!(file->fek_enc = malloc(file->fek_enc_size)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (pad(fek_buffer, fek_buffer_size, TEE_AES_BLOCK_SIZE, file->fek_enc, &file->fek_enc_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }

    TEE_GenerateRandom(file->fek_enc_iv, IV_SIZE);
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMACSHA256_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        return res;
    }

    res = TEE_SetOperationKey(op_handle, file->pobj->tss->db->bk);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        return res;
    }

    TEE_MACInit(op_handle, NULL, 0);
    res = TEE_MACComputeFinal(op_handle, file->pobj->tss->uuid, sizeof(TEE_UUID), tsk_buffer, &tsk_buffer_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        return res;
    }

    TEE_FreeOperation(op_handle);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BIT_SIZE, &tsk);
    if (res != TEE_SUCCESS)
    {
        return res;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, tsk_buffer, tsk_buffer_size);
    res = TEE_PopulateTransientObject(tsk, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(tsk);
        return res;
    }

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT, AES_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(tsk);
        return res;
    }

    res = TEE_SetOperationKey(op_handle, tsk);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(tsk);
        return res;
    }

    TEE_CipherInit(op_handle, file->fek_enc_iv, IV_SIZE);

    tmp_fek_enc_size = file->fek_enc_size;
    res = TEE_CipherUpdate(op_handle, file->fek_enc, file->fek_enc_size, file->fek_enc, &tmp_fek_enc_size);
    if ((res != TEE_SUCCESS) || (tmp_fek_enc_size != file->fek_enc_size))
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(tsk);
        return res;
    }

    TEE_FreeOperation(op_handle);

    TEE_FreeTransientObject(tsk);

    return res;
}

TEE_Result trx_file_decrypt(trx_file *file)
{
    TEE_Result res;
    TEE_OperationHandle op_handle;
    uint32_t tmp_data_enc_size, tmp_fek_enc_size;
    TEE_ObjectHandle fek, tsk;
    uint8_t fek_buffer[AES_KEY_SIZE];
    size_t fek_buffer_size;
    uint8_t tsk_buffer[HMACSHA256_TAG_SIZE];
    uint32_t tsk_buffer_size;
    TEE_Attribute attr = {};

    fek_buffer_size = AES_KEY_SIZE;
    tsk_buffer_size = HMACSHA256_TAG_SIZE;

    // Generate TSK

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMACSHA256_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        return res;
    }
    res = TEE_SetOperationKey(op_handle, file->pobj->tss->db->bk);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        return res;
    }
    TEE_MACInit(op_handle, NULL, 0);
    res = TEE_MACComputeFinal(op_handle, file->pobj->tss->uuid, sizeof(TEE_UUID), tsk_buffer, &tsk_buffer_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        return res;
    }
    TEE_FreeOperation(op_handle);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BIT_SIZE, &tsk);
    if (res != TEE_SUCCESS)
    {
        return res;
    }
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, tsk_buffer, tsk_buffer_size);
    res = TEE_PopulateTransientObject(tsk, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(tsk);
        return res;
    }

    // Decrypt FEK

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT, AES_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(tsk);
        return res;
        
    }
    res = TEE_SetOperationKey(op_handle, tsk);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(tsk);
        return res;
    }
    TEE_CipherInit(op_handle, file->fek_enc_iv, IV_SIZE);
    tmp_fek_enc_size = file->fek_enc_size;
    res = TEE_CipherUpdate(op_handle, file->fek_enc, file->fek_enc_size, file->fek_enc, &tmp_fek_enc_size);
    if ((res != TEE_SUCCESS) || (tmp_fek_enc_size != file->fek_enc_size))
    {
        
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(tsk);
        return res;
    }
    TEE_FreeOperation(op_handle);
    TEE_FreeTransientObject(tsk);

    if (unpad(file->fek_enc, file->fek_enc_size, TEE_AES_BLOCK_SIZE, fek_buffer, &fek_buffer_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BIT_SIZE, &fek);
    if (res != TEE_SUCCESS)
    {
        return res;
    }
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, fek_buffer, fek_buffer_size);
    res = TEE_PopulateTransientObject(fek, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(fek);
        return res;
    }

    // Decrypt data

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, AES_KEY_BIT_SIZE);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeTransientObject(fek);
        return res;
    }
    res = TEE_SetOperationKey(op_handle, fek);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return res;
    }
    res = TEE_AEInit(op_handle, file->data_enc_nonce, NONCE_SIZE, TAG_BIT_SIZE, 0, file->data_enc_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return res;
    }
    tmp_data_enc_size = file->data_enc_size;
    res = TEE_AEDecryptFinal(op_handle, file->data_enc, file->data_enc_size, file->data_enc, &tmp_data_enc_size, file->tag, TAG_SIZE);
    if ((res != TEE_SUCCESS) || (tmp_data_enc_size != file->data_enc_size))
    {
        TEE_FreeOperation(op_handle);
        TEE_FreeTransientObject(fek);
        return res;
    }
    TEE_FreeOperation(op_handle);
    TEE_FreeTransientObject(fek);

    file->pobj->data_size = 0;
    free(file->pobj->data);

    if (unpad(file->data_enc, file->data_enc_size, TEE_AES_BLOCK_SIZE, NULL, &file->pobj->data_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }
    if (!(file->pobj->data = malloc(file->pobj->data_size)))
    {
        return TEE_ERROR_GENERIC;
    }
    if (unpad(file->data_enc, file->data_enc_size, TEE_AES_BLOCK_SIZE, file->pobj->data, &file->pobj->data_size) != 0)
    {
        return TEE_ERROR_GENERIC;
    }
    return res;
}

int trx_file_serialize(trx_file *file, void *data, size_t *data_size)
{
    size_t tmp_data_size;
    uint8_t *cpy_ptr;

    if (!file)
    {
        return 1;
    }
    tmp_data_size = sizeof(size_t) + file->bk_enc_size + IV_SIZE +
                    sizeof(size_t) + file->fek_enc_size + NONCE_SIZE +
                    sizeof(size_t) + file->data_enc_size + TAG_SIZE;

    if (!data && !(*data_size))
    {
        *data_size = tmp_data_size;
        return 0;
    }

    if (!data || (*data_size != tmp_data_size))
    {
        return 1;
    }

    cpy_ptr = data;

    memcpy(cpy_ptr, &(file->bk_enc_size), sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    memcpy(cpy_ptr, file->bk_enc, file->bk_enc_size);
    cpy_ptr += file->bk_enc_size;
    memcpy(cpy_ptr, file->fek_enc_iv, IV_SIZE);
    cpy_ptr += IV_SIZE;
    memcpy(cpy_ptr, &(file->fek_enc_size), sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    memcpy(cpy_ptr, file->fek_enc, file->fek_enc_size);
    cpy_ptr += file->fek_enc_size;
    memcpy(cpy_ptr, file->data_enc_nonce, NONCE_SIZE);
    cpy_ptr += NONCE_SIZE;
    memcpy(cpy_ptr, &(file->data_enc_size), sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    memcpy(cpy_ptr, file->data_enc, file->data_enc_size);
    cpy_ptr += file->data_enc_size;
    memcpy(cpy_ptr, file->tag, TAG_SIZE);
    cpy_ptr += TAG_SIZE;
    return 0;
}

int trx_file_deserialize(trx_file *file, void *data, size_t data_size)
{
    uint8_t *cpy_ptr;
    size_t left;

    if (!data || !file || !data_size)
    {
        return 1;
    }

    cpy_ptr = data;
    left = data_size;
    if (left < sizeof(size_t))
    {
        return 1;
    }
    memcpy(&(file->bk_enc_size), cpy_ptr, sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    left -= sizeof(size_t);

    if (left < file->bk_enc_size)
    {
        return 1;
    }
    if (!(file->bk_enc = malloc(file->bk_enc_size)))
    {
        return 1;
    }
    memcpy(file->bk_enc, cpy_ptr, file->bk_enc_size);
    cpy_ptr += file->bk_enc_size;
    left -= file->bk_enc_size;

    if (left < IV_SIZE)
    {
        return 1;
    }
    memcpy(file->fek_enc_iv, cpy_ptr, IV_SIZE);
    cpy_ptr += IV_SIZE;
    left -= IV_SIZE;

    if (left < sizeof(size_t))
    {
        return 1;
    }
    memcpy(&(file->fek_enc_size), cpy_ptr, sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    left -= sizeof(size_t);

    if (left < file->fek_enc_size)
    {
        return 1;
    }
    if (!(file->fek_enc = malloc(file->fek_enc_size)))
    {
        return 1;
    }
    memcpy(file->fek_enc, cpy_ptr, file->fek_enc_size);
    cpy_ptr += file->fek_enc_size;
    left -= file->fek_enc_size;

    if (left < NONCE_SIZE)
    {
        return 1;
    }
    memcpy(file->data_enc_nonce, cpy_ptr, NONCE_SIZE);
    cpy_ptr += NONCE_SIZE;
    left -= NONCE_SIZE;

    if (left < sizeof(size_t))
    {
        return 1;
    }
    memcpy(&(file->data_enc_size), cpy_ptr, sizeof(size_t));
    cpy_ptr += sizeof(size_t);
    left -= sizeof(size_t);

    if (left < file->data_enc_size)
    {
        return 1;
    }
    if (!(file->data_enc = malloc(file->data_enc_size)))
    {
        return 1;
    }
    memcpy(file->data_enc, cpy_ptr, file->data_enc_size);
    cpy_ptr += file->data_enc_size;
    left -= file->data_enc_size;

    if (left < TAG_SIZE)
    {
        return 1;
    }
    memcpy(file->tag, cpy_ptr, TAG_SIZE);
    cpy_ptr += TAG_SIZE;
    left -= TAG_SIZE;

    if (left != 0)
    {
        return 1;
    }
    return 0;
}