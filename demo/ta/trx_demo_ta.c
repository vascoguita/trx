#include <tee_internal_api.h>
#include <string.h>

#include <trx_demo_ta.h>
#include <trx/trx.h>

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    const void *id = "id";
    size_t id_size = strlen(id);
    const void *data = "data";
    size_t data_size = strlen(data);
    TEE_Result res;

    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

	res = trx_write(id, id_size, data, data_size);
    if(res != TEE_SUCCESS) {
        DMSG("trx_write failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    (void)&params;
    (void)&cmd;
    (void)&param_types;
    (void)&sess_ctx;

    return TEE_ERROR_NOT_SUPPORTED;
}