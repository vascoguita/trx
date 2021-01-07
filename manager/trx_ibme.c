#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <ibme/ibme.h>

#include "trx_ibme.h"
#include "utils.h"

trx_ibme *trx_ibme_init(void)
{
    trx_ibme *ibme;

    DMSG("initializing ibme");

    if ((ibme = (struct _trx_ibme *)malloc(sizeof(struct _trx_ibme))) == NULL)
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    if (!(ibme->pairing = (pairing_t *)malloc(sizeof(pairing_t))))
    {
        EMSG("failed calling function \'malloc\'");
        trx_ibme_clear(ibme);
        return NULL;
    }
    ibme->mpk = NULL;
    ibme->ek = NULL;
    ibme->dk = NULL;
    ibme->param_str = NULL;
    ibme->param_str_size = 0;

    DMSG("initialized ibme");

    return ibme;
}

void trx_ibme_clear(trx_ibme *ibme)
{
    DMSG("clearing ibme");

    if (ibme)
    {
        MPK_clear(ibme->mpk);
        EK_clear(ibme->ek);
        DK_clear(ibme->dk);
        if (ibme->pairing)
        {
            pairing_clear(*(ibme->pairing));
            free(ibme->pairing);
        }
        free(ibme->param_str);
    }
    free(ibme);

    DMSG("cleared ibme");
}

trx_ibme *trx_ibme_create(char *param_str, size_t param_str_size, char *mpk_str, size_t mpk_str_size,
                          char *ek_str, size_t ek_str_size, char *dk_str, size_t dk_str_size)
{
    trx_ibme *ibme;
    TEE_Result res;

    DMSG("creating ibme, param_str: \"%s\" with param_str_size: %zu, mpk_str: \"%s\" with mpk_str_size: %zu, "
         "ek_str: \"%s\" with ek_str_size: %zu, dk_str: \"%s\" with dk_str_size: %zu, ",
         param_str, param_str_size, mpk_str, mpk_str_size, ek_str, ek_str_size, dk_str, dk_str_size);

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("failed calling function \'trx_ibme_init\'");
        return NULL;
    }
    res = trx_ibme_set_param_str(ibme, param_str, param_str_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_set_param_str\'");
        trx_ibme_clear(ibme);
        return NULL;
    }
    res = trx_ibme_set_mpk(ibme, mpk_str, mpk_str_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_set_mpk\'");
        trx_ibme_clear(ibme);
        return NULL;
    }
    res = trx_ibme_set_ek(ibme, ek_str, ek_str_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_set_ek\'");
        trx_ibme_clear(ibme);
        return NULL;
    }
    res = trx_ibme_set_dk(ibme, dk_str, dk_str_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_set_dk\'");
        trx_ibme_clear(ibme);
        return NULL;
    }

    DMSG("created ibme");

    return ibme;
}

TEE_Result trx_ibme_set_param_str(trx_ibme *ibme, char *param_str, size_t param_str_size)
{
    DMSG("setting ibme param_str: \"%s\", param_str_size: %zu", param_str, param_str_size);

    if (!ibme || !param_str || !param_str_size)
    {
        EMSG("failed checking if ibme is not NULL or param_str is not NULL or param_str_size is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme->param_str = strndup(param_str, param_str_size)))
    {
        EMSG("failed calling function \'strndup\'");
        return TEE_ERROR_GENERIC;
    }
    ibme->param_str_size = param_str_size;

    if (1 == pairing_init_set_str(*(ibme->pairing), ibme->param_str))
    {
        EMSG("failed calling function \'pairing_init_set_str\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme->mpk = MPK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'MPK_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme->ek = EK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'EK_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme->dk = DK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'DK_init\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set ibme param_str: \"%s\", param_str_size: %zu", ibme->param_str, ibme->param_str_size);

    return TEE_SUCCESS;
}

TEE_Result trx_ibme_set_mpk(trx_ibme *ibme, char *mpk_str, size_t mpk_str_size)
{
    DMSG("setting ibme mpk, mpk_str: \"%s\", mpk_str_size: %zu", mpk_str, mpk_str_size);

    if (!ibme || !mpk_str || !mpk_str_size)
    {
        EMSG("failed checking if ibme is not NULL or mpk_str is not NULL or mpk_str_size is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    if (0 == MPK_set_str(mpk_str, mpk_str_size, ibme->mpk))
    {
        EMSG("failed calling function \'MPK_set_str\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set ibme mpk");

    return TEE_SUCCESS;
}

TEE_Result trx_ibme_set_dk(trx_ibme *ibme, char *dk_str, size_t dk_str_size)
{
    DMSG("setting ibme dk, dk_str: \"%s\", dk_str_size: %zu", dk_str, dk_str_size);

    if (!ibme || !dk_str || !dk_str_size)
    {
        EMSG("failed checking if ibme is not NULL or dk_str is not NULL or dk_str_size is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    if (0 == DK_set_str(dk_str, dk_str_size, ibme->dk))
    {
        EMSG("failed calling function \'DK_set_str\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set ibme dk");

    return TEE_SUCCESS;
}

TEE_Result trx_ibme_set_ek(trx_ibme *ibme, char *ek_str, size_t ek_str_size)
{
    DMSG("setting ibme ek, ek_str: \"%s\", ek_str_size: %zu", ek_str, ek_str_size);

    if (!ibme || !ek_str || !ek_str_size)
    {
        EMSG("failed checking if ibme is not NULL or ek_str is not NULL or ek_str_size is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    if (0 == EK_set_str(ek_str, ek_str_size, ibme->ek))
    {
        EMSG("failed calling function \'EK_set_str\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set ibme ek");

    return TEE_SUCCESS;
}

int trx_ibme_snprint(char *s, size_t n, trx_ibme *ibme)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", ibme->param_str_size);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", ibme->param_str);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MPK_snprint(s + result, left, ibme->mpk);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = EK_snprint(s + result, left, ibme->ek);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = DK_snprint(s + result, left, ibme->dk);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int trx_ibme_set_str(char *s, size_t n, trx_ibme *ibme)
{
    size_t result, left;
    int status;

    result = 0;
    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((ibme->param_str_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", ibme->param_str_size);
    clip_sub(&result, status, &left, n);
    if ((ibme->param_str = (void *)malloc(ibme->param_str_size)) == NULL)
    {
        return 0;
    }
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((ibme->param_str = strndup(s + result, ibme->param_str_size - 1)) == NULL)
    {
        return 0;
    }
    if (1 == pairing_init_set_str(*(ibme->pairing), ibme->param_str))
    {
        return 0;
    }
    if (!(ibme->mpk = MPK_init(*(ibme->pairing))))
    {
        return 0;
    }
    if (!(ibme->ek = EK_init(*(ibme->pairing))))
    {
        return 0;
    }
    if (!(ibme->dk = DK_init(*(ibme->pairing))))
    {
        return 0;
    }
    status = strlen(ibme->param_str);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = MPK_set_str(s + result, left, ibme->mpk)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = EK_set_str(s + result, left, ibme->ek)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = DK_set_str(s + result, left, ibme->dk)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

TEE_Result trx_ibme_save(trx_ibme *ibme)
{
    int ibme_str_len, id_size;
    char *ibme_str = NULL, *id = NULL;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;

    DMSG("saving ibme");

    if ((ibme_str_len = trx_ibme_snprint(NULL, 0, ibme)) < 1)
    {
        EMSG("failed calling function \'trx_ibme_snprint\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if ((ibme_str = (char *)malloc((ibme_str_len + 1) * sizeof(char))) == NULL)
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (ibme_str_len != trx_ibme_snprint(ibme_str, (ibme_str_len + 1), ibme))
    {
        EMSG("failed calling function \'trx_ibme_snprint\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    id_size = strlen(trx_ibme_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_MemMove(id, trx_ibme_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
                                     TEE_HANDLE_NULL, ibme_str, ibme_str_len + 1, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_CreatePersistentObject\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("saved ibme");

out:
    TEE_Free(id);
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    free(ibme_str);

    return res;
}

TEE_Result trx_ibme_load(trx_ibme *ibme)
{
    int id_size;
    char *ibme_str = NULL, *id = NULL;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_ObjectInfo obj_info;

    DMSG("loading ibme");

    id_size = strlen(trx_ibme_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_MemMove(id, trx_ibme_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_OpenPersistentObject\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_GetObjectInfo1\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(ibme_str = (char *)malloc(obj_info.dataSize)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = TEE_ReadObjectData(obj, ibme_str, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize)
    {
        EMSG("failed calling function \'TEE_ReadObjectData\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (trx_ibme_set_str(ibme_str, obj_info.dataSize, ibme) == 0)
    {
        EMSG("failed calling function \'trx_ibme_set_str\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("loaded ibme");

out:
    if(obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    free(ibme_str);
    TEE_Free(id);
    return res;
}