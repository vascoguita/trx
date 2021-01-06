#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <ree_fs_api.h>

#include "trx_manager_ta.h"
#include "trx_manager_private.h"
#include "trx_manager_defaults.h"
#include "trx_pobj.h"
#include "trx_tss.h"
#include "trx_path.h"
#include "utils.h"
#include "trx_volume.h"
#include "trx_volume_table.h"
#include "trx_ibme.h"
#include "trx_authorization.h"
#include <ibme/ibme.h>
#include "trx_keys.h"

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    char *param_str, *mpk_str, *ek_str, *dk_str;
    size_t param_str_size, mpk_str_size, ek_str_size, dk_str_size;
    trx_ibme *ibme;
    TEE_Result res;
    (void)&sess_ctx;

    DMSG("has been called");

    //FIXME, prevent from being called more than once

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    param_str = params[0].memref.buffer;
    param_str_size = (size_t)params[0].memref.size;
    mpk_str = params[1].memref.buffer;
    mpk_str_size = (size_t)params[1].memref.size;
    ek_str = params[2].memref.buffer;
    ek_str_size = (size_t)params[2].memref.size;
    dk_str = params[3].memref.buffer;
    dk_str_size = (size_t)params[3].memref.size;

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("failed calling function \'trx_ibme_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (!(ibme->param_str = strndup(param_str, param_str_size)))
    {
        EMSG("failed calling function \'strndup\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    ibme->param_str_size = param_str_size;
    if (1 == pairing_init_set_str(*(ibme->pairing), ibme->param_str))
    {
        EMSG("failed calling function \'pairing_init_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (!(ibme->mpk = MPK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'MPK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (!(ibme->ek = EK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'EK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (!(ibme->dk = DK_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'DK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == MPK_set_str(mpk_str, mpk_str_size, ibme->mpk))
    {
        EMSG("failed calling function \'MPK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == EK_set_str(ek_str, ek_str_size, ibme->ek))
    {
        EMSG("failed calling function \'EK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == DK_set_str(dk_str, dk_str_size, ibme->dk))
    {
        EMSG("failed calling function \'DK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    res = trx_ibme_save(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_save\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    trx_ibme_clear(ibme);
    return res;
}

TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    TEE_Identity identity;
    TEE_UUID *uuid;
    TEE_Result res;
    char *path, *mount_point, *id, *ree_dirname, *ree_basename;
    void *data;
    size_t path_size, mount_point_size, id_size, ree_dirname_size, ree_basename_size, data_size;
    trx_volume *volume;
    trx_tss *tss;
    trx_pobj *pobj;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    (void)&path_size;

    DMSG("writing data: \"%s\" with data_size: %zu to path: \"%s\" with path_size: %zu",
         (char *)data, data_size, (char *)path, path_size);

    if (!(mount_point = dirname(path)))
    {
        EMSG("failed calling function \'dirname\'");
        return TEE_ERROR_GENERIC;
    }
    mount_point_size = strlen(mount_point) + 1;
    if (!(volume = trx_volume_table_get(volume_table, mount_point, mount_point_size)))
    {
        if (!(ree_dirname = trx_volume_table_gen_ree_dirname(volume_table)))
        {
            EMSG("failed calling function \'trx_volume_table_gen_ree_dirname\'");
            return TEE_ERROR_GENERIC;
        }
        ree_dirname_size = strlen(ree_dirname) + 1;
        if (!(volume = trx_volume_create(mount_point, mount_point_size, ree_dirname, ree_dirname_size)))
        {
            EMSG("failed calling function \'trx_volume_create\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_volume_table_add(volume_table, volume);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_table_add\'");
            trx_volume_clear(volume);
            return TEE_ERROR_GENERIC;
        }
    }
    if (!trx_volume_is_loaded(volume))
    {
        res = trx_volume_load(volume);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_load\'");
            return TEE_ERROR_GENERIC;
        }
    }
    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_GetPropertyAsIdentity\'");
        return TEE_ERROR_GENERIC;
    }
    uuid = &identity.uuid;
    if (!(tss = trx_volume_get(volume, uuid)))
    {
        if (!(tss = trx_tss_create(uuid)))
        {
            EMSG("failed calling function \'trx_tss_create\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_volume_add(volume, tss);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_add\'");
            trx_tss_clear(tss);
            return TEE_ERROR_GENERIC;
        }
    }
    if (!(id = basename(path)))
    {
        EMSG("failed calling function \'basename\'");
        return TEE_ERROR_GENERIC;
    }
    id_size = strlen(id) + 1;
    if (!(pobj = trx_tss_get(tss, id, id_size)))
    {
        if (!(ree_basename = trx_volume_gen_ree_basename(volume)))
        {
            EMSG("failed calling function \'trx_volume_gen_ree_basename\'");
            return TEE_ERROR_GENERIC;
        }
        ree_basename_size = strlen(ree_basename) + 1;
        if (!(pobj = trx_pobj_create(ree_basename, ree_basename_size, id, id_size, data, data_size)))
        {
            EMSG("failed calling function \'trx_pobj_create\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_tss_add(tss, pobj);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_tss_add\'");
            trx_pobj_clear(pobj);
            return TEE_ERROR_GENERIC;
        }
    }
    else
    {
        res = trx_pobj_set_data(pobj, data, data_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_data\'");
            return TEE_ERROR_GENERIC;
        }
    }
    res = trx_pobj_save(pobj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_save\'");
        return TEE_ERROR_GENERIC;
    }
    res = trx_volume_save(volume);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_save\'");
        return TEE_ERROR_GENERIC;
    }
    res = trx_volume_table_save(volume_table);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_table_save\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("wrote data: \"%s\" with data_size: %zu to ree_dirname: \"%s\" with ree_dirname_size: %zu and ree_basename: \"%s\" with ree_basename_size: %zu"
         " and mount_point: \"%s\" with mount_point_size: %zu and id: \"%s\" with id_size: %zu and version: %lu",
         (char *)(pobj->data), pobj->data_size, pobj->tss->volume->ree_dirname, pobj->tss->volume->ree_dirname_size, pobj->ree_basename,
         pobj->ree_basename_size, pobj->tss->volume->mount_point, pobj->tss->volume->mount_point_size, pobj->id, pobj->id_size, pobj->version);
    return res;
}

TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *data_size;
    TEE_Identity identity;
    TEE_UUID *uuid;
    TEE_Result res;
    char *path, *mount_point, *id;
    void *data;
    size_t path_size, mount_point_size, id_size;
    trx_pobj *pobj;
    trx_tss *tss;
    trx_volume *volume;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = &(params[1].memref.size);

    (void)&path_size;

    if (!(mount_point = dirname(path)))
    {
        EMSG("failed calling function \'dirname\'");
        return TEE_ERROR_GENERIC;
    }
    mount_point_size = strlen(mount_point) + 1;
    if (!(volume = trx_volume_table_get(volume_table, mount_point, mount_point_size)))
    {
        EMSG("failed calling function \'trx_volume_table_get\'");
        return TEE_ERROR_GENERIC;
    }
    if (!trx_volume_is_loaded(volume))
    {
        res = trx_volume_load(volume);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_load\'");
            return TEE_ERROR_GENERIC;
        }
    }
    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_GetPropertyAsIdentity\'");
        return TEE_ERROR_GENERIC;
    }
    uuid = &identity.uuid;
    if (!(tss = trx_volume_get(volume, uuid)))
    {
        EMSG("failed calling function \'trx_volume_get\'");
        return TEE_ERROR_GENERIC;
    }
    if (!(id = basename(path)))
    {
        EMSG("failed calling function \'basename\'");
        return TEE_ERROR_GENERIC;
    }
    id_size = strlen(id) + 1;
    if (!(pobj = trx_tss_get(tss, id, id_size)))
    {
        EMSG("failed calling function \'trx_tss_get\'");
        return TEE_ERROR_GENERIC;
    }
    if ((*data_size > (uint32_t)pobj->data_size) || (*data_size == 0))
    {
        *data_size = (uint32_t)pobj->data_size;
    }
    if (data != NULL)
    {
        if (!trx_pobj_is_loaded(pobj))
        {
            res = trx_pobj_load(pobj);
            if (res != TEE_SUCCESS)
            {
                EMSG("failed calling function \'trx_pobj_load\'");
                return TEE_ERROR_GENERIC;
            }
        }
        memcpy(data, pobj->data, (size_t)*data_size);
    }
    return res;
}

TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    /*uint32_t exp_param_types, *list_size;
    TEE_Identity identity;
    TEE_Result res;
    char *list;
    TEE_UUID *uuid;
    volume_list_head *volume_lh;
    path_list_head *path_lh;
    int tmp_list_size;*/

    (void)&sess_ctx;
    (void)&param_types;
    (void)&params;

    DMSG("has been called");

    /*exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    list = params[0].memref.buffer;
    list_size = &(params[0].memref.size);

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x", res);
        return res;
    }
    uuid = &identity.uuid;

    if (!(volume_lh = trx_volume_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_volume_list_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (trx_volume_list_load(volume_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_volume_list_load\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    
    if (!(path_lh = trx_path_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_path_list_init\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    if (trx_volume_list_to_path_list(path_lh, uuid, volume_lh) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_volume_list_to_path_list\'");
        trx_volume_list_clear(volume_lh);
        trx_path_list_clear(path_lh);
        return TEE_ERROR_GENERIC;
    }
    if ((tmp_list_size = trx_path_list_snprint(list, *list_size, path_lh) + 1) < 1)
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_path_list_snprint\'");
        trx_volume_list_clear(volume_lh);
        trx_path_list_clear(path_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_path_list_clear(path_lh);
    trx_volume_list_clear(volume_lh);
    *list_size = (uint32_t)tmp_list_size;
    return res;*/

    //FIXME
    return TEE_ERROR_GENERIC;
}

TEE_Result mount(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    /*uint32_t exp_param_types;
    char *S, *ree_dirname, *mount_point;
    size_t S_size, ree_dirname_size, mount_point_size;
    trx_volume *volume;
    volume_list_head *volume_lh;
    TEE_Result res;*/

    (void)&sess_ctx;
    (void)&param_types;
    (void)&params;

    /*
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    S = params[0].memref.buffer;
    S_size = params[0].memref.size;
    ree_dirname = params[1].memref.buffer;
    ree_dirname_size = (size_t)params[1].memref.size;
    mount_point = params[2].memref.buffer;
    mount_point_size = (size_t)params[2].memref.size;

    if(!trx_authorization_mount(mount_point, S)) {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_authorization_mount\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(volume = trx_volume_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(volume->mount_point = strndup(mount_point, mount_point_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'strdup\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }
    volume->mount_point_size = mount_point_size;
    volume->ree_dirname = strndup(ree_dirname, ree_dirname_size);
    volume->ree_dirname_size = ree_dirname_size;

    if (!(volume_lh = trx_volume_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_list_init\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }
    if (trx_volume_list_load(volume_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_list_load\'");
        trx_volume_clear(volume);
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    if (trx_volume_list_add(volume, volume_lh) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_list_add\'");
        trx_volume_clear(volume);
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    if(trx_volume_import(volume, S, S_size) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_import\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_list_save(volume_lh);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_volume_list_save\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_volume_list_clear(volume_lh);
    return res;*/

    //FIXME
    return TEE_ERROR_GENERIC;
}

TEE_Result share(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    /*uint32_t exp_param_types;
    char *R, *mount_point;
    size_t R_size, mount_point_size;
    volume_list_head *volume_lh;
    trx_volume *volume;*/

    (void)&sess_ctx;
    (void)&param_types;
    (void)&params;

    DMSG("has been called");
    /*
    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    R = params[0].memref.buffer;
    R_size = params[0].memref.size;
    mount_point = params[1].memref.buffer;
    mount_point_size = params[1].memref.size;

    if (!(volume_lh = trx_volume_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_volume_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (trx_volume_list_load(volume_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_volume_list_load\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }
    if (!(volume = trx_volume_list_get(mount_point, mount_point_size, volume_lh)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_volume_list_get\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }

    if(!trx_authorization_share(mount_point, R)) {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_authorization_share\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }

    if(trx_volume_share(volume, R, R_size) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_volume_share\'");
        trx_volume_list_clear(volume_lh);
        return TEE_ERROR_GENERIC;
    }

    trx_volume_list_clear(volume_lh);
    return TEE_SUCCESS;*/

    //FIXME
    return TEE_ERROR_GENERIC;
}