#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <trx_demo_ta.h>
#include <trx/trx.h>
#include <trx_path.h>

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    void *read_data;
    size_t read_data_size;
    TEE_Result res;
    path_list_head *lh;
    path_entry *e;

    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

	res = trx_setup("trx", strlen("trx") + 1);
    if(res != TEE_SUCCESS) {
        DMSG("trx_setup failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }

	res = trx_write("test_path_1", strlen("test_path_1") + 1, "data", strlen("data") + 1);
    if(res != TEE_SUCCESS) {
        DMSG("trx_write failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }
    res = trx_write("ka", 3, "ola", 4);
    if(res != TEE_SUCCESS) {
        DMSG("trx_write failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }

    if(!(lh = trx_path_list_init())) {
        DMSG("trx_list failed with code 0x%x", res);
        return TEE_ERROR_GENERIC;
    }

    res = trx_list(lh);
    if (res != TEE_SUCCESS) {
        DMSG("trx_list failed with code 0x%x", res);
        trx_path_list_clear(lh);
        return TEE_ERROR_GENERIC;
    }
    SLIST_FOREACH(e, lh, _path_entries) {
        read_data_size = e->path->data_size;
        read_data = malloc(read_data_size);
        res = trx_read(e->path->path, e->path->path_size, read_data, &read_data_size);
        if (res != TEE_SUCCESS) {
            DMSG("trx_read failed with code 0x%x", res);
            free(read_data);
            trx_path_list_clear(lh);
            return TEE_ERROR_GENERIC;
        }
        DMSG("trx_read returned:\nread_data:%s\nread_data_size:%zu", (char *) read_data, read_data_size);
        free(read_data);
    }
    trx_path_list_clear(lh);

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