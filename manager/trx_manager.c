#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <ree_fs_api.h>

#include <trx_manager_ta.h>
#include "trx_manager_private.h"
#include "trx_setup.h"
#include "trx_db.h"
#include "trx_tss.h"

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    trx_setup *setup;
    trx_db *db;
    int fd;
    TEE_Result res;

	(void)&sess_ctx;

	DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    trx_setup_init(&setup);
    setup->path_size = (size_t)params[0].memref.size;
    setup->path = strndup(params[0].memref.buffer, setup->path_size);
    res = trx_setup_save(setup);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_setup_save\' with code 0x%x", res);
        trx_setup_clear(setup);
        return res;
    }

    res = ree_fs_api_create(setup->path, setup->path_size, &fd);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'ree_fs_create\' with code 0x%x", res);
        trx_setup_clear(setup);
        return res;
    }
    trx_setup_clear(setup);
    trx_db_init(&db);
    if(trx_db_out_str(db, fd) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_out_str\'");
        trx_db_clear(db);
        ree_fs_api_close(fd);
        return TEE_ERROR_GENERIC;
    }
    trx_db_clear(db);
    ree_fs_api_close(fd);
	return res;
}

TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    TEE_Result res;
    int fd;
    char *filename;
    size_t filename_size;
    void *data;
    size_t data_size;
    TEE_Identity identity;
    tss_list_head tss_h;
    trx_tss *tss;
    char *tss_list_str;
    int tss_list_str_len;
    char *tss_str;
    int tss_str_len;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    DMSG("Param 0:\nbuffer:\'%s\'\nsize:%zu\n"
         "Param 1:\nbuffer:\'%s\'\nsize:%zu",
         (char *)params[0].memref.buffer, (size_t)params[0].memref.size,
         (char *)params[1].memref.buffer, (size_t)params[1].memref.size);


    filename_size = params[0].memref.size;
    filename = params[0].memref.buffer;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;


    res = ree_fs_api_open(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_open\' with code 0x%x", res);
        return res;
    }

    res = ree_fs_api_read(fd, 0, data, &data_size);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_read\' with code 0x%x", res);
    }

    ree_fs_api_close(fd);


    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }

    if(trx_tss_init(&tss) != 0) {
        return TEE_ERROR_GENERIC;
    }
    memcpy(tss->uuid, &identity.uuid, sizeof(TEE_UUID));

    if((tss_str_len = trx_tss_snprint(NULL, 0, tss)) < 0 ) {
        trx_tss_clear(tss);
        return TEE_ERROR_GENERIC;
    }

    if((tss_str = (char *) malloc((tss_str_len + 1) * sizeof(char))) == NULL) {
        trx_tss_clear(tss);
        return TEE_ERROR_GENERIC;
    }

    if(tss_str_len != trx_tss_snprint(tss_str, (tss_str_len + 1) , tss)) {
        trx_tss_clear(tss);
        return TEE_ERROR_GENERIC;
    }

    //trx_tss_clear(tss);

    DMSG("%s", tss_str);

    free(tss_str);

    trx_tss_list_init(&tss_h);
    trx_tss_list_add(tss, &tss_h);
    if((tss_list_str_len = trx_tss_list_snprint(NULL, 0, &tss_h)) < 0 ) {
        trx_tss_list_clear(&tss_h);
        return TEE_ERROR_GENERIC;
    }
    if((tss_list_str = (char *) malloc((tss_list_str_len + 1) * sizeof(char))) == NULL) {
        trx_tss_list_clear(&tss_h);
        return TEE_ERROR_GENERIC;
    }
    if(tss_list_str_len != trx_tss_list_snprint(tss_list_str, (tss_list_str_len + 1) , &tss_h)) {
        trx_tss_list_clear(&tss_h);
        return TEE_ERROR_GENERIC;
    }
    trx_tss_list_clear(&tss_h);
    DMSG("%s", tss_list_str);
    free(tss_list_str);

    res = ree_fs_api_create(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'ree_fs_create\' with code 0x%x", res);
        return res;
    }

    res = ree_fs_api_write(fd, 0, data, data_size);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'ree_fs_write\' with code 0x%x", res);
    }

    ree_fs_api_close(fd);

    return res;
}

TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    TEE_Result res;
    int fd;
    char *filename;
    size_t filename_size;
    void *data;
    size_t data_size;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    filename_size = params[0].memref.size;
    filename = params[0].memref.buffer;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    res = ree_fs_api_open(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_open\' with code 0x%x", res);
        return res;
    }

    res = ree_fs_api_read(fd, 0, data, &data_size);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_read\' with code 0x%x", res);
    }

    ree_fs_api_close(fd);

    return res;
}

TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
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