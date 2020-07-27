#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <ree_fs_api.h>

#include "trx_manager_private.h"
#include "trx_manager_defaults.h"
#include "trx_db_map.h"
#include "trx_db.h"
#include "trx_tss.h"
#include "utils.h"

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    char *db_path;
    size_t db_path_size;
    trx_db *db;
    trx_db_map *db_map;

	(void)&sess_ctx;

	DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    db_path = params[0].memref.buffer;
    db_path_size = (size_t)params[0].memref.size;

    if(trx_db_init(&db) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_save(db, db_path, db_path_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_save\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    trx_db_clear(db);

    if(trx_db_map_init(&db_map) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_map_init\'");
        return TEE_ERROR_GENERIC;
    }
    db_map->path_size = db_path_size;
    db_map->path = strndup(db_path, db_path_size - 1);
    if(trx_db_map_save(db_map, db_map_pobj_id, db_map_pobj_id_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_map_save\'");
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    trx_db_map_clear(db_map);

    return TEE_SUCCESS;
}

TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types;
    TEE_Identity identity;
    TEE_Result res;
    void *id, *data;
    char *dir, *filename;
    size_t id_size, filename_size, data_size;
    TEE_UUID *uuid;
    trx_db_map *db_map;
    trx_db *db;
    trx_pobj *pobj;
    int fd;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    id = params[0].memref.buffer;
    id_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }
    uuid = &identity.uuid;

    if(trx_db_map_init(&db_map) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_map_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_map_load(db_map, db_map_pobj_id, db_map_pobj_id_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_map_load\'");
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_init(&db) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_init\'");
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_load(db, db_map->path, db_map->path_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_load\'");
        trx_db_clear(db);
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    if((pobj = trx_db_get(uuid, id, id_size, db)) == NULL) {
        if((pobj = trx_db_insert(uuid, id, id_size, db)) == NULL) {
            EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_insert\'");
            trx_db_clear(db);
            trx_db_map_clear(db_map);
            return TEE_ERROR_GENERIC;
        }
        if(trx_db_save(db, db_map->path, db_map->path_size) != 0) {
            EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_save\'");
            trx_db_clear(db);
            trx_db_map_clear(db_map);
            return TEE_ERROR_GENERIC;
        }
    }
    dir = dirname(db_map->path);
    filename_size = snprintf(NULL, 0, "%s/%lu", dir, pobj->ree_id) + 1;
    if((filename = (char *)malloc(filename_size * sizeof(char))) == NULL) {
        trx_db_map_clear(db_map);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    snprintf(filename, filename_size, "%s/%lu", dir, pobj->ree_id);
    trx_db_map_clear(db_map);
    trx_db_clear(db);
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
    TEE_Identity identity;
    TEE_Result res;
    void *id, *data;
    char *dir, *filename;
    size_t id_size, filename_size, data_size;
    TEE_UUID *uuid;
    trx_db_map *db_map;
    trx_db *db;
    trx_pobj *pobj;
    int fd;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    id = params[0].memref.buffer;
    id_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,  "gpd.client.identity", &identity);
    if(res != TEE_SUCCESS) {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x" , res);
        return res;
    }
    uuid = &identity.uuid;

    if(trx_db_map_init(&db_map) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_map_init\'");
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_map_load(db_map, db_map_pobj_id, db_map_pobj_id_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_map_load\'");
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    if(trx_db_init(&db) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_init\'");
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    DMSG("\n\n\'%s\', %zu\n\n", db_map->path, db_map->path_size);
    if(trx_db_load(db, db_map->path, db_map->path_size) != 0) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_load\'");
        trx_db_clear(db);
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    if((pobj = trx_db_get(uuid, id, id_size, db)) == NULL) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_get\'");
        trx_db_clear(db);
        trx_db_map_clear(db_map);
        return TEE_ERROR_GENERIC;
    }
    dir = dirname(db_map->path);
    filename_size = snprintf(NULL, 0, "%s/%lu", dir, pobj->ree_id) + 1;
    if((filename = (char *)malloc(filename_size * sizeof(char))) == NULL) {
        trx_db_map_clear(db_map);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    snprintf(filename, filename_size, "%s/%lu", dir, pobj->ree_id);
    trx_db_map_clear(db_map);
    trx_db_clear(db);

    res = ree_fs_api_open(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_open\' with code 0x%x", res);
        return res;
    }

    res = ree_fs_api_read(fd, 0, data, &data_size);
    if(res != TEE_SUCCESS) {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'ree_fs_read\' with code 0x%x", res);
    }

    params[1].memref.size = data_size;

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