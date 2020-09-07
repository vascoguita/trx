#include <tee_internal_api.h>
#include <string.h>
#include <trx_setup_ta.h>
#include <trx/trx.h>
#include <tui/tui.h>

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    TEE_Result res;

    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TUI->setup("10.0.2.2", 9000);
    if(res != TEE_SUCCESS) {
        EMSG("TUI failed to setup with code 0x%x", res);
        return res;
    }

    res = trx_setup("trx", strlen("trx") + 1);
    if(res != TEE_SUCCESS) {
        DMSG("trx_setup failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }

	return res;
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