#include "trx_authentication.h"

#include <tee_internal_api.h>
#include <tui/tui.h>
#include <string.h>
#include <stdlib.h>

trx_authentication *trx_authentication_init(void)
{
    trx_authentication *auth;

    DMSG("initializing auth");

    if ((auth = (struct _trx_authentication *)malloc(sizeof(struct _trx_authentication))) == NULL)
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    
    auth->pin = NULL;
    auth->pin_size = 0;

    DMSG("initialized auth");
    return auth;
}

void trx_authentication_clear(trx_authentication *auth)
{
    DMSG("clearing auth");

    if (auth)
    {
        if(auth->pin)
        {
            free(auth->pin);
        }
        free(auth);
    }

    DMSG("cleared auth");
}

TEE_Result trx_authentication_save(trx_authentication *auth)
{
    int id_size;
    char *id = NULL;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;

    DMSG("saving auth, pin: \"%s\" with pin_size %zu", auth->pin, auth->pin_size);

    id_size = strlen(trx_authentication_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_MemMove(id, trx_authentication_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
                                     TEE_HANDLE_NULL, auth->pin, auth->pin_size, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_CreatePersistentObject\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("saved auth, pin: \"%s\" with pin_size %zu", auth->pin, auth->pin_size);

out:
    TEE_Free(id);
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }

    return res;
}

TEE_Result trx_authentication_load(trx_authentication *auth)
{
    int id_size;
    char *id = NULL;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_ObjectInfo obj_info;

    DMSG("loading auth");

    id_size = strlen(trx_authentication_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    TEE_MemMove(id, trx_authentication_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_OpenPersistentObject\'");
        goto out;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_GetObjectInfo1\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    auth->pin_size = obj_info.dataSize;
    if(!(auth->pin = malloc(auth->pin_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = TEE_ReadObjectData(obj, auth->pin, auth->pin_size, &count);
    if (res != TEE_SUCCESS || count != auth->pin_size)
    {
        EMSG("failed calling function \'TEE_ReadObjectData\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("loaded auth, pin: \"%s\" with pin_size %zu", auth->pin, auth->pin_size);

out:
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    TEE_Free(id);
    return res;
}

TEE_Result trx_authentication_setup(trx_authentication *auth)
{
    size_t input_size = 100;
    char input[100];
    TEE_Result res;

    DMSG("setting auth");

    res = TUI->input("Enter PIN:", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TUI->input\'");
        return TEE_ERROR_GENERIC;
    }

    auth->pin = strdup(input);
    auth->pin_size = strlen(auth->pin) + 1;

    res = trx_authentication_save(auth);
    if(res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_authentication_save\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set auth, pin: \"%s\" with pin_size %zu", auth->pin, auth->pin_size);

    return TEE_SUCCESS;
}

bool trx_authentication_check(trx_authentication *auth, char *input)
{
    size_t input_size;

    input_size = strlen(input) + 1;

    DMSG("checking auth, pin: \"%s\" with pin_size %zu, input: \"%s\" with input_size %zu", auth->pin, auth->pin_size, input, input_size);

    if(auth->pin_size != input_size)
    {
        DMSG("authentication failed");
        return false;
    }
    if(strncmp(auth->pin, input, auth->pin_size))
    {
        DMSG("authentication failed");
        return false;
    }
    DMSG("authentication succeeded");
    return true;
}