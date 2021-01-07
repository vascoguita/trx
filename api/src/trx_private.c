#include "trx_private.h"

#include <tee_internal_api.h>
#include <trx_manager_ta.h>

TEE_Result invoke_trx_manager_cmd(uint32_t cmd, uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]) {
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    TEE_Result res;
    TEE_TASessionHandle sess;
    uint32_t origin, sess_param_types;
    sess_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, sess_param_types, NULL, &sess, &origin);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x", res, origin);
        return res;
    }
    res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd, param_types, params, &origin);
    if ((res != TEE_SUCCESS) || (res != TEE_ERROR_SHORT_BUFFER)) {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x", res, origin);
    }
    TEE_CloseTASession(sess);
    return res;
}
