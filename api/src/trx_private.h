#ifndef TRX_TRX_PRIVATE_H
#define TRX_TRX_PRIVATE_H

#include <tee_internal_api.h>

TEE_Result invoke_trx_manager_cmd(uint32_t cmd, uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif //TRX_TRX_PRIVATE_H
