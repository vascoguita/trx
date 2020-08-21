#ifndef TRX_TRX_MANAGER_PRIVATE_H
#define TRX_TRX_MANAGER_PRIVATE_H

#include <tee_internal_api.h>

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result mount(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result share(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);

#endif //TRX_TRX_MANAGER_PRIVATE_H
