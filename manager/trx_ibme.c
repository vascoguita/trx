#include "utils.h"
#include "trx_manager_defaults.h"
#include "trx_ibme.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <ibme/ibme.h>

trx_ibme *trx_ibme_init(void)
{
    trx_ibme *ibme;
    if((ibme = (struct _trx_ibme*) malloc(sizeof(struct _trx_ibme))) == NULL) {
        return NULL;
    }
    ibme->mpk = NULL;
    ibme->ek = NULL;
    ibme->dk = NULL;
    ibme->param_str = NULL;
    ibme->param_str_size = 0;
    return ibme;
}

void trx_ibme_clear(trx_ibme *ibme)
{
    if (ibme) {
        MPK_clear(ibme->mpk);
        EK_clear(ibme->ek);
        DK_clear(ibme->dk);
        free(ibme->param_str);
    }
    free(ibme);
}

int trx_ibme_snprint(char *s, size_t n, trx_ibme *ibme)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", ibme->param_str_size);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", ibme->param_str);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MPK_snprint(s + result, left, ibme->mpk);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = EK_snprint(s + result, left, ibme->ek);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = DK_snprint(s + result, left, ibme->dk);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int trx_ibme_set_str(char *s, size_t n, trx_ibme *ibme)
{
    size_t result, left;
    int status;
    pairing_t pairing;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((ibme->param_str_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", ibme->param_str_size);
    clip_sub(&result, status, &left, n);
    if((ibme->param_str = (void *)malloc(ibme->param_str_size)) == NULL) {
        return 0;
    }
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((ibme->param_str = strndup(s + result, ibme->param_str_size - 1)) == NULL){
        return 0;
    }
    if(1 == pairing_init_set_str(pairing, ibme->param_str)) {
        return 0;
    }
    if(1 == MPK_init(pairing, &(ibme->mpk))) {
        pairing_clear(pairing);
        return 0;
    }
    if(1 == EK_init(pairing, &(ibme->ek))) {
        pairing_clear(pairing);
        return 0;
    }
    if(1 == DK_init(pairing, &(ibme->dk))) {
        pairing_clear(pairing);
        return 0;
    }
    pairing_clear(pairing);
    status = strlen(ibme->param_str);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = MPK_set_str(s + result, left, ibme->mpk)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = EK_set_str(s + result, left, ibme->ek)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = DK_set_str(s + result, left, ibme->dk)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

TEE_Result trx_ibme_save(trx_ibme *ibme)
{
    int ibme_str_len, id_size;
    char *ibme_str, *id;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj;

    if((ibme_str_len = trx_ibme_snprint(NULL, 0, ibme)) < 1) {
        return TEE_ERROR_GENERIC;
    }
    if((ibme_str = (char *) malloc((ibme_str_len + 1) * sizeof(char))) == NULL) {
        return TEE_ERROR_GENERIC;
    }
    if(ibme_str_len != trx_ibme_snprint(ibme_str, (ibme_str_len + 1) , ibme)) {
        free(ibme_str);
        return TEE_ERROR_GENERIC;
    }

    id_size = strlen(DEFAULT_IBME_ID) + 1;
    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, DEFAULT_IBME_ID, id_size);

    //FIXME NO OVERWRITE READONLY
    flags = TEE_DATA_FLAG_ACCESS_READ |	TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
            TEE_HANDLE_NULL, ibme_str, ibme_str_len + 1, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
    }
    TEE_Free(id);
    TEE_CloseObject(obj);
    free(ibme_str);
    return res;
}

TEE_Result trx_ibme_load(trx_ibme *ibme) {
    int id_size;
    char *ibme_str, *id;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj;
    TEE_ObjectInfo obj_info;

    id_size = strlen(DEFAULT_IBME_ID) + 1;
    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, DEFAULT_IBME_ID, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(id);
        return res;
    }
    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        TEE_CloseObject(obj);
        TEE_Free(id);
        return res;
    }
    if((ibme_str = (char*) malloc(obj_info.dataSize)) == NULL) {
        TEE_CloseObject(obj);
        TEE_Free(id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    res = TEE_ReadObjectData(obj, ibme_str, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize) {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 "over %u", res, count, obj_info.dataSize);
        TEE_CloseObject(obj);
        TEE_Free(id);
        free(ibme_str);
        return res;
    }
    TEE_CloseObject(obj);
    TEE_Free(id);

    if(trx_ibme_set_str(ibme_str, obj_info.dataSize, ibme) == 0) {
        res = TEE_ERROR_GENERIC;
    }

    free(ibme_str);
    return res;
}