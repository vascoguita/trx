#include <tee_internal_api.h>
#include <trx_manager_ta.h>
#include "trx_manager_private.h"

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;

    DMSG("has been called");

    if(!(volume_table = trx_volume_table_init()))
    {
        EMSG("failed calling function \'trx_volume_table_init\'");
        return TEE_ERROR_GENERIC;
    }
    
    if(trx_volume_table_exists())
    {
        res = trx_volume_table_load(volume_table);
        if(res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_table_load\'");
            trx_volume_table_clear(volume_table);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");
    
    trx_volume_table_clear(volume_table);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx)
{
    uint32_t exp_param_types;

    (void)&params;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    TEE_Identity identity;

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("TUI failed to retrieve client identity, res=0x%08x", res);
        return res;
    }

    switch (cmd)
    {
    case TA_TRX_MANAGER_CMD_SETUP:
        return setup(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_WRITE:
        if (identity.login != TEE_LOGIN_TRUSTED_APP)
        {
            EMSG("Access Denied: Only TAs are allowed to use TRX");
            return TEE_ERROR_GENERIC;
        }
        return write(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_READ:
        if (identity.login != TEE_LOGIN_TRUSTED_APP)
        {
            EMSG("Access Denied: Only TAs are allowed to use TRX");
            return TEE_ERROR_GENERIC;
        }
        return read(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_LIST:
        if (identity.login != TEE_LOGIN_TRUSTED_APP)
        {
            EMSG("Access Denied: Only TAs are allowed to use TRX");
            return TEE_ERROR_GENERIC;
        }
        return list(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_MOUNT:
        if (identity.login != TEE_LOGIN_TRUSTED_APP)
        {
            EMSG("Access Denied: Only TAs are allowed to use TRX");
            return TEE_ERROR_GENERIC;
        }
        return mount(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_SHARE:
        if (identity.login != TEE_LOGIN_TRUSTED_APP)
        {
            EMSG("Access Denied: Only TAs are allowed to use TRX");
            return TEE_ERROR_GENERIC;
        }
        return share(sess_ctx, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}