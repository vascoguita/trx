#include <tee_internal_api.h>
#include <trx_manager_ta.h>
#include "trx_manager_private.h"

trx_volume_table *volume_table = NULL;
trx_ibme *ibme = NULL;
trx_authentication *auth = NULL;

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;

    DMSG("has been called");

    if (!(auth = trx_authentication_init()))
    {
        EMSG("failed calling function \'trx_authentication_init\'");
        return TEE_ERROR_GENERIC;
    }
    res = trx_authentication_load(auth);
    if (res == TEE_ERROR_ITEM_NOT_FOUND)
    {
        res = trx_authentication_setup(auth);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_authentication_setup\'");
            return TEE_ERROR_GENERIC;
        }
    } else if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_authentication_load\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("failed calling function \'trx_ibme_init\'");
        return TEE_ERROR_GENERIC;
    }

    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("failed calling function \'trx_ibme_load\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(volume_table = trx_volume_table_init()))
    {
        EMSG("failed calling function \'trx_volume_table_init\'");
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_table_load(volume_table);
    if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("failed calling function \'trx_volume_table_load\'");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");

    if (ibme)
    {
        trx_ibme_clear(ibme);
    }
    if (volume_table)
    {
        trx_volume_table_clear(volume_table);
    }
    if (auth)
    {
        trx_authentication_clear(auth);
    }
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
        if (trx_ibme_isloaded(ibme))
        {
            EMSG("Access Denied: TRX has already been provided with IB-ME keys");
            return TEE_ERROR_GENERIC;
        }
        return setup(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_WRITE:
        if ((identity.login != TEE_LOGIN_TRUSTED_APP) || !trx_ibme_isloaded(ibme))
        {
            EMSG("Access Denied: Write entry point is only accessible to TAs and after setup");
            return TEE_ERROR_GENERIC;
        }
        return write(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_READ:
        if ((identity.login != TEE_LOGIN_TRUSTED_APP) || !trx_ibme_isloaded(ibme))
        {
            EMSG("Access Denied: Read entry point is only accessible to TAs and after setup");
            return TEE_ERROR_GENERIC;
        }
        return read(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_MOUNT:
        if ((identity.login != TEE_LOGIN_TRUSTED_APP) || !trx_ibme_isloaded(ibme))
        {
            EMSG("Access Denied: Mount entry point is only accessible to TAs and after setup");
            return TEE_ERROR_GENERIC;
        }
        return mount(sess_ctx, param_types, params);
    case TA_TRX_MANAGER_CMD_SHARE:
        if ((identity.login != TEE_LOGIN_TRUSTED_APP) || !trx_ibme_isloaded(ibme))
        {
            EMSG("Access Denied: Share entry point is only accessible to TAs and after setup");
            return TEE_ERROR_GENERIC;
        }
        return share(sess_ctx, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}