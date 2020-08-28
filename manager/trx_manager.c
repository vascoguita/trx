#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <ree_fs_api.h>

#include "trx_manager_ta.h"
#include "trx_manager_private.h"
#include "trx_manager_defaults.h"
#include "trx_tss.h"
#include "trx_path.h"
#include "utils.h"
#include "trx_db.h"

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    char *ree_dirname;
    size_t ree_dirname_size;
    trx_db *db;
    db_list_head *db_lh;
    TEE_Result res;
	(void)&sess_ctx;

	DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    ree_dirname = params[0].memref.buffer;
    ree_dirname_size = (size_t)params[0].memref.size;

    if(!(db = trx_db_init())){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(!(db->mount_point = strdup(dirname(NULL)))){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'strdup\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    db->mount_point_size = strlen(db->mount_point) + 1;
    db->ree_dirname = strndup(ree_dirname, ree_dirname_size);
    db->ree_dirname_size = ree_dirname_size;
    if(trx_db_save(db) != 0){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_save\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    if(!(db_lh = trx_db_list_init())){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_init\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_add(db, db_lh) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_add\'");
        trx_db_clear(db);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    res = trx_db_list_save(db_lh);
    if(res != TEE_SUCCESS){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    TEE_Identity identity;
    TEE_UUID *uuid;
    TEE_Result res;
    char *path;
    void *data;
    size_t path_size, data_size;
    db_list_head *db_lh;
    trx_pobj *pobj;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }
    uuid = &identity.uuid;

    if(!(db_lh = trx_db_list_init())) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_load(db_lh) != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if((pobj = trx_db_list_get_pobj(uuid, path, path_size, db_lh)) == NULL) {
        if((pobj = trx_db_list_insert_pobj(uuid, path, path_size, db_lh)) == NULL) {
            EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_insert_pobj\'");
            trx_db_list_clear(db_lh);
            return TEE_ERROR_GENERIC;
        }
    }
    pobj->data_size = data_size;
    pobj->data = malloc(data_size);
    memcpy(pobj->data, data, data_size);
    if(trx_db_save(pobj->db) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if(trx_pobj_save(pobj) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_pobj_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types, *data_size;
    TEE_Identity identity;
    TEE_UUID *uuid;
    TEE_Result res;
    char *path;
    void *data;
    size_t path_size;
    db_list_head *db_lh;
    trx_pobj *pobj;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = &(params[1].memref.size);

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }
    uuid = &identity.uuid;

    if(!(db_lh = trx_db_list_init())) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_load(db_lh) != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if((pobj = trx_db_list_get_pobj(uuid, path, path_size, db_lh)) == NULL) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_get_pobj\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if((*data_size > (uint32_t)pobj->data_size) || (*data_size == 0)) {
        *data_size = (uint32_t)pobj->data_size;
    }
    if(data != NULL) {
        if(trx_pobj_load(pobj) != 0) {
            EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_pobj_load\'");
            trx_db_list_clear(db_lh);
            return TEE_ERROR_GENERIC;
        }
        memcpy(data, pobj->data, (size_t) * data_size);
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types, *list_size;
    TEE_Identity identity;
    TEE_Result res;
    char *list;
    TEE_UUID *uuid;
    db_list_head *db_lh;
    path_list_head *path_lh;
    int tmp_list_size;

    (void)&sess_ctx;
    (void)&param_types;
    (void)&params;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    list = params[0].memref.buffer;
    list_size = &(params[0].memref.size);

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }
    uuid = &identity.uuid;

    if(!(db_lh = trx_db_list_init())) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_load(db_lh) != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if(!(path_lh = trx_path_list_init())) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_path_list_init\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_to_path_list(path_lh, uuid, db_lh) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_to_path_list\'");
        trx_db_list_clear(db_lh);
        trx_path_list_clear(path_lh);
        return TEE_ERROR_GENERIC;
    }
    if((tmp_list_size = trx_path_list_snprint(list, *list_size, path_lh) + 1) < 1) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_path_list_snprint\'");
        trx_db_list_clear(db_lh);
        trx_path_list_clear(path_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_path_list_clear(path_lh);
    trx_db_list_clear(db_lh);
    *list_size = (uint32_t)tmp_list_size;
    return res;
}

TEE_Result mount(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    char *ree_dirname, *mount_point;
    size_t ree_dirname_size, mount_point_size;
    trx_db *db;
    db_list_head *db_lh;
    TEE_Result res;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ree_dirname = params[0].memref.buffer;
    ree_dirname_size = (size_t)params[0].memref.size;
    mount_point = params[1].memref.buffer;
    mount_point_size = (size_t)params[1].memref.size;

    if(!(db = trx_db_init())){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(!(db->mount_point = strndup(mount_point, mount_point_size))){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'strdup\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    db->mount_point_size = mount_point_size;
    db->ree_dirname = strndup(ree_dirname, ree_dirname_size);
    db->ree_dirname_size = ree_dirname_size;
    if(trx_db_load(db) != 0){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_save\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if(!(db_lh = trx_db_list_init())){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_init\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_load(db_lh) != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_list_add(db, db_lh) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_add\'");
        trx_db_clear(db);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    res = trx_db_list_save(db_lh);
    if(res != TEE_SUCCESS){
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result share(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    (void)&sess_ctx;
    (void)&param_types;
    (void)&params;
    return TEE_SUCCESS;
}