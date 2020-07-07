#include <tee_internal_api.h>
#include <ree_fs_api.h>

#include <trx_manager_ta.h>

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    
    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)&sess_ctx;

    DMSG("has been called");
}

static TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;

	(void)&sess_ctx;
    (void)&params;

	DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

	return TEE_SUCCESS;
}

static TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    TEE_Result res;

    (void)&sess_ctx;
    (void)&params;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = ree_fs_write((char *)params[0].memref.buffer, (size_t)params[0].memref.size,
            (char *)params[1].memref.buffer, (size_t)params[1].memref.size);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'ree_fs_write\' with code 0x%x", res);
    }
    return res;
}

static TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;

    (void)&sess_ctx;
    (void)&params;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;

    (void)&sess_ctx;
    (void)&params;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    switch(cmd) {
        case TA_TRX_MANAGER_CMD_SETUP:
            return setup(sess_ctx, param_types, params);
        case TA_TRX_MANAGER_CMD_WRITE:
            return write(sess_ctx, param_types, params);
        case TA_TRX_MANAGER_CMD_READ:
            return read(sess_ctx, param_types, params);
        case TA_TRX_MANAGER_CMD_LIST:
            return list(sess_ctx, param_types, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}