#include "trx.h"
#include "trx_private.h"
#include <trx_manager_ta.h>
#include <stdlib.h>
#include "trx_path.h"

#include <tee_internal_api.h>

TEE_Result trx_setup(const char *param_str, size_t param_str_size,
                     const char *mpk_str, size_t mpk_str_size,
                     const char *ek_str, size_t ek_str_size,
                     const char *dk_str, size_t dk_str_size) {
    TEE_Result res;
    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (char *)param_str;
    params[0].memref.size = param_str_size;
    params[1].memref.buffer = (char *)mpk_str;
    params[1].memref.size = mpk_str_size;
    params[2].memref.buffer = (char *)ek_str;
    params[2].memref.size = ek_str_size;
    params[3].memref.buffer = (char *)dk_str;
    params[3].memref.size = dk_str_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_SETUP, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_SETUP with code 0x%x", res);
    }

    return res;
}

TEE_Result trx_write(const char *path, size_t path_size,
        const void *data, size_t data_size) {
    TEE_Result res;
    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (char *)path;
    params[0].memref.size = path_size;
    params[1].memref.buffer = (void *)data;
    params[1].memref.size = data_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_WRITE, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_WRITE with code 0x%x", res);
    }

    return res;
}

TEE_Result trx_read(const char *path, size_t path_size,
        void *data, size_t *data_size) {
    TEE_Result res;

    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (char *)path;
    params[0].memref.size = path_size;
    params[1].memref.buffer = data;
    params[1].memref.size = *data_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_READ, param_types, params);
    if ((res != TEE_SUCCESS) || (res != TEE_ERROR_SHORT_BUFFER)) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_READ with code 0x%x", res);
    }
    *data_size = params[1].memref.size;

    return res;
}

TEE_Result trx_list(path_list_head *h) {
    TEE_Result res;
    char *list;
    size_t list_size;

    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = NULL;
    params[0].memref.size = 0;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_LIST, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_LIST with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }
    list_size = params[0].memref.size;

    if(!(list = (char *)malloc(list_size))) {
        return TEE_ERROR_GENERIC;
    }
    params[0].memref.buffer = list;
    params[0].memref.size = list_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_LIST, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_LIST with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }
    list_size = params[0].memref.size;

    if(trx_path_list_set_str(list, list_size, h) == 0) {
        free(list);
        return TEE_ERROR_GENERIC;
    }

    free(list);

    return res;
}

TEE_Result trx_mount(const unsigned char *S, size_t S_size, const char *ree_dirname, size_t ree_dirname_size,
                     const char *mount_point, size_t mount_point_size)
{
    TEE_Result res;
    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (unsigned char *)S;
    params[0].memref.size = S_size;
    params[1].memref.buffer = (char *)ree_dirname;
    params[1].memref.size = ree_dirname_size;
    params[2].memref.buffer = (char *)mount_point;
    params[2].memref.size = mount_point_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_MOUNT, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_MOUNT with code 0x%x", res);
    }

    return res;
}

TEE_Result trx_share(const unsigned char *R, size_t R_size, const char *mount_point, size_t mount_point_size)
{
    TEE_Result res;
    uint32_t param_types;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (unsigned char *)R;
    params[0].memref.size = R_size;
    params[1].memref.buffer = (char *)mount_point;
    params[1].memref.size = mount_point_size;

    res = invoke_trx_manager_cmd(TA_TRX_MANAGER_CMD_SHARE, param_types, params);
    if (res != TEE_SUCCESS) {
        EMSG("invoke_trx_manager_cmd failed to invoke command TA_TRX_MANAGER_CMD_SHARE with code 0x%x", res);
    }

    return res;
}