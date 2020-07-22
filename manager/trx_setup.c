#include "trx_setup.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"

#include <tee_internal_api.h>

int trx_setup_init(trx_setup **setup) {
    if((*setup = (struct _trx_setup*) malloc(sizeof(struct _trx_setup))) == NULL) {
        return 1;
    }
    (*setup)->path = NULL;
    (*setup)->path_size = 0;
    return 0;
}

void trx_setup_clear(trx_setup *setup) {
    if(setup != NULL) {
        if(setup->path != NULL) {
            free(setup->path);
        }
        free(setup);
    }
}

int trx_setup_snprint(char *s, size_t n, trx_setup *setup) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", setup->path_size);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", setup->path);
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

int trx_setup_set_str(char *s, size_t n, trx_setup *setup) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((setup->path_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", setup->path_size);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    setup->path = strndup(s + result, setup->path_size);
    if(!setup->path) {
        return 0;
    }
    status = setup->path_size - 1;
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

TEE_Result trx_setup_save(trx_setup *setup)
{
    int setup_str_len;
    char *setup_str, *id;
    TEE_Result res;
    uint32_t flags;
    size_t id_size;
    TEE_ObjectHandle obj;

    if((setup_str_len = trx_setup_snprint(NULL, 0, setup)) < 1) {
        return TEE_ERROR_GENERIC;
    }

    if((setup_str = (char *) malloc((setup_str_len + 1) * sizeof(char))) == NULL) {
        return TEE_ERROR_GENERIC;
    }

    if(setup_str_len != trx_setup_snprint(setup_str, (setup_str_len + 1) , setup)) {
        free(setup_str);
        return TEE_ERROR_GENERIC;
    }

    id_size = strlen(setup_pobj_id) + 1;

    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, setup_pobj_id, id_size);

    // FIXME enable only read
    flags = TEE_DATA_FLAG_ACCESS_READ |	TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, TEE_HANDLE_NULL, setup_str, setup_str_len + 1, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
    }
    TEE_Free(id);
    TEE_CloseObject(obj);
    free(setup_str);
    return res;
}