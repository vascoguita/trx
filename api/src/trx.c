#include "trx.h"
#include "trx_private.h"
#include <trx_manager_ta.h>

#include <tee_internal_api.h>

TEE_Result trx_setup(void) {
    return TEE_SUCCESS;
}

TEE_Result trx_write(const void *id, size_t id_size,
        const void *data, size_t data_size) {
    TEE_Result res;
    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (void *)id;
    params[0].memref.size = id_size;
    params[1].memref.buffer = (void *)data;
    params[1].memref.size = data_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_WRITE, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_WRITE with code 0x%x", res);
    }

    return res;
}

TEE_Result trx_read(const void *objectID, size_t objectIDLen,
        void *data, size_t dataLen) {
    (void)&data;
    (void)&dataLen;

    if(objectID == NULL || objectIDLen < 1) {
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result trx_list(void *objectIdList) {
    (void)&objectIdList;
    return TEE_SUCCESS;
}