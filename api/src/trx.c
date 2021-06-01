#include <tee_internal_api.h>
#include <trx_manager_ta.h>

#include "trx.h"

TEE_Result trx_handle_init(trx_handle *handle)
{
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    uint32_t origin, sess_param_types;
    sess_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    return TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, sess_param_types, NULL, handle, &origin);
}

void trx_handle_clear(trx_handle handle)
{
    TEE_CloseTASession(handle);
}

TEE_Result trx_write(trx_handle handle, const char *path, size_t path_size, const void *data, size_t data_size)
{
    TEE_Result res;
    uint32_t param_types, origin;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (char *)path;
    params[0].memref.size = path_size;
    params[1].memref.buffer = (void *)data;
    params[1].memref.size = data_size;

    res = TEE_InvokeTACommand(handle, TEE_TIMEOUT_INFINITE, TA_TRX_MANAGER_CMD_WRITE, param_types, params, &origin);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x", res, origin);
        return TEE_ERROR_GENERIC;
    }

    return res;
}

TEE_Result trx_read(trx_handle handle, const char *path, size_t path_size,
                    void *data, size_t *data_size)
{
    TEE_Result res;
    uint32_t param_types, origin;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (char *)path;
    params[0].memref.size = path_size;
    params[1].memref.buffer = data;
    params[1].memref.size = *data_size;

    res = TEE_InvokeTACommand(handle, TEE_TIMEOUT_INFINITE, TA_TRX_MANAGER_CMD_READ, param_types, params, &origin);
    if ((res != TEE_SUCCESS) && (res != TEE_ERROR_SHORT_BUFFER))
    {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x", res, origin);
        return TEE_ERROR_GENERIC;
    }
    *data_size = params[1].memref.size;

    return res;
}

TEE_Result trx_share(trx_handle handle, const unsigned char *R, size_t R_size, const char *mount_point, size_t mount_point_size,
                     const char *label, size_t label_size, void *dst, size_t *dst_size)
{
    TEE_Result res;
    uint32_t param_types, origin;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (unsigned char *)R;
    params[0].memref.size = R_size;
    params[1].memref.buffer = (char *)mount_point;
    params[1].memref.size = mount_point_size;
    params[2].memref.buffer = (char *)label;
    params[2].memref.size = label_size;
    params[3].memref.buffer = dst;
    params[3].memref.size = *dst_size;

    res = TEE_InvokeTACommand(handle, TEE_TIMEOUT_INFINITE, TA_TRX_MANAGER_CMD_SHARE, param_types, params, &origin);
    if ((res != TEE_SUCCESS) && (res != TEE_ERROR_SHORT_BUFFER))
    {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x", res, origin);
        return TEE_ERROR_GENERIC;
    }
    *dst_size = params[3].memref.size;

    return res;
}

TEE_Result trx_mount(trx_handle handle, const unsigned char *S, size_t S_size, const char *ree_dirname, size_t ree_dirname_size,
                     const char *mount_point, size_t mount_point_size, char *src, size_t src_size)
{
    TEE_Result res;
    uint32_t param_types, origin;
    TEE_Param params[4];

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);

    TEE_MemFill(params, 0, sizeof(params));
    params[0].memref.buffer = (unsigned char *)S;
    params[0].memref.size = S_size;
    params[1].memref.buffer = (char *)ree_dirname;
    params[1].memref.size = ree_dirname_size;
    params[2].memref.buffer = (char *)mount_point;
    params[2].memref.size = mount_point_size;
    params[3].memref.buffer = (char *)src;
    params[3].memref.size = src_size;

    res = TEE_InvokeTACommand(handle, TEE_TIMEOUT_INFINITE, TA_TRX_MANAGER_CMD_MOUNT, param_types, params, &origin);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x", res, origin);
        return TEE_ERROR_GENERIC;
    }

    return res;
}