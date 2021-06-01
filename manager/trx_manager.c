#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>

#include "trx_manager_private.h"
#include "trx_manager_ta.h"
#include "trx_volume_table.h"
#include "trx_volume.h"
#include "trx_tss.h"
#include "trx_pobj.h"
#include "trx_utils.h"
#include "trx_ibme.h"
#include "trx_authorization.h"
#include "trx_authentication.h"

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    char *data;
    size_t data_size;
    TEE_Result res;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    data = params[0].memref.buffer;
    data_size = (size_t)params[0].memref.size;

    if (trx_ibme_isloaded(ibme))
    {
        EMSG("failed checking if IB-ME key already exist");
        return TEE_ERROR_GENERIC;
    }

    res = trx_ibme_deserialize(ibme, data, data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_deserialize\'");
        return TEE_ERROR_GENERIC;
    }

    res = trx_ibme_save(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_save\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("set up trx ibme keys");
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
    trx_volume *volume = NULL;
    trx_tss *tss = NULL;
    trx_pobj *pobj = NULL;

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
        if (!(volume = trx_volume_create(mount_point, mount_point_size, ree_dirname, ree_dirname_size,
                                         ibme->udid, ibme->udid_size)))
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
        if (!(pobj = trx_pobj_create(ree_basename, ree_basename_size, id, id_size, ibme->udid,
                                     ibme->udid_size, data, data_size)))
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
    res = trx_pobj_set_udid(pobj, ibme->udid, ibme->udid_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_data\'");
        return TEE_ERROR_GENERIC;
    }
    res = trx_pobj_save(pobj);
    if (res != TEE_SUCCESS)
    {
        trx_pobj_clear_data(pobj);
        EMSG("failed calling function \'trx_pobj_save\'");
        return TEE_ERROR_GENERIC;
    }
    trx_pobj_clear_data(pobj);
    res = trx_volume_set_udid(volume, ibme->udid, ibme->udid_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_data\'");
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

    DMSG("wrote data: \"%s\" with data_size: %zu to ree_dirname: \"%s\" with ree_dirname_size: %zu and "
         "ree_basename: \"%s\" with ree_basename_size: %zu and mount_point: \"%s\" with mount_point_size: "
         "%zu and id: \"%s\" with id_size: %zu and udid: \"%s\" with udid_size: %zu and version: %lu",
         (char *)data, pobj->data_size, pobj->tss->volume->ree_dirname, pobj->tss->volume->ree_dirname_size,
         pobj->ree_basename, pobj->ree_basename_size, pobj->tss->volume->mount_point,
         pobj->tss->volume->mount_point_size, pobj->id, pobj->id_size, (char *)pobj->udid, pobj->udid_size,
         pobj->version);
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

    DMSG("checking \"data\" buffer size from path: \"%s\" with path_size: %zu", (char *)path, path_size);

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

    if (!data)
    {
        *data_size = (uint32_t)pobj->data_size;
        DMSG("defining required buffer size to read pobj: %zu", (size_t)*data_size);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*data_size < (uint32_t)pobj->data_size)
    {
        EMSG("failed checking size of \"data\" buffer, provided_size: %zu, required_size: %zu",
             (size_t)*data_size, pobj->data_size);
        return TEE_ERROR_GENERIC;
    }

    DMSG("reading pobj");
    res = trx_pobj_load(pobj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_load\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("Copying pobj data to \"data\" buffer");
    memcpy(data, pobj->data, (size_t)*data_size);

    DMSG("Setting data_size to size of actual read data");
    *data_size = (uint32_t)pobj->data_size;

    trx_pobj_clear_data(pobj);

    DMSG("read pobj data: \"%s\" with data_size: %zu from path: \"%s\" with path_size: %zu",
         (char *)data, (size_t)*data_size, (char *)path, path_size);

    return TEE_SUCCESS;
}

TEE_Result share(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *dst_size;
    char *R, *mount_point, *label;
    size_t R_size, mount_point_size, label_size, tmp_dst_size;
    trx_volume *volume;
    uint8_t *dst = NULL;
    TEE_Result res;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    R = params[0].memref.buffer;
    R_size = params[0].memref.size;
    mount_point = params[1].memref.buffer;
    mount_point_size = params[1].memref.size;
    label = params[2].memref.buffer;
    label_size = params[2].memref.size;
    dst = params[3].memref.buffer;
    dst_size = &(params[3].memref.size);

    DMSG("sharing volume mounted on mount_point: \"%s\" with mount_point size: %zu and"
         " label: \"%s\" with label_point size: %zu with receiver: \"%s\" with receiver size %zu",
         mount_point, mount_point_size, label, label_size, R, R_size);

    if (!(volume = trx_volume_table_get(volume_table, mount_point, mount_point_size)))
    {
        EMSG("failed calling function \'trx_volume_table_get\'");
        return TEE_ERROR_GENERIC;
    }

    if (!trx_authorization_share(auth, mount_point, R, volume->version, label))
    {
        EMSG("failed calling function \'trx_authorization_share\'");
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_set_label(volume, label, label_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_set_label\'");
        return TEE_ERROR_GENERIC;
    }

    tmp_dst_size = (size_t)*dst_size;
    res = trx_volume_share(volume, R, R_size, ibme, dst, &tmp_dst_size);
    if (res == TEE_ERROR_SHORT_BUFFER)
    {
        *dst_size = (uint32_t)tmp_dst_size;
        DMSG("defining required buffer size to share volume: %zu", (size_t)*dst_size);
        return res;
    }
    else if (res == TEE_SUCCESS)
    {
        *dst_size = (uint32_t)tmp_dst_size;
        DMSG("shared volume mounted on mount_point: \"%s\" with mount_point size: %zu and"
             " label: \"%s\" with label_point size: %zu with receiver: \"%s\" with receiver size %zu",
             mount_point, mount_point_size, label, label_size, R, R_size);
        return res;
    }
    else
    {
        EMSG("failed calling function \'trx_volume_share\'");
        return TEE_ERROR_GENERIC;
    }
}

TEE_Result mount(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    char *S, *ree_dirname, *mount_point, *src;
    size_t S_size, ree_dirname_size, mount_point_size, src_size;
    trx_volume *volume;
    TEE_Result res;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    S = params[0].memref.buffer;
    S_size = params[0].memref.size;
    ree_dirname = params[1].memref.buffer;
    ree_dirname_size = (size_t)params[1].memref.size;
    mount_point = params[2].memref.buffer;
    mount_point_size = (size_t)params[2].memref.size;
    src = params[3].memref.buffer;
    src_size = (size_t)params[3].memref.size;

    DMSG("mounting volume from sender: \"%s\" with sender size: %zu and ree_dirname: \"%s\""
         "with ree_dirname_size: %zu on mount_point: \"%s\" with mount_point size: %zu",
         S, S_size, ree_dirname, ree_dirname_size, mount_point, mount_point_size);

    if (!(volume = trx_volume_init()))
    {
        EMSG("failed calling function \'trx_volume_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (!(volume->mount_point = strndup(mount_point, mount_point_size)))
    {
        EMSG("failed calling function \'strndup\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }
    volume->mount_point_size = mount_point_size;
    if (!(volume->ree_dirname = strndup(ree_dirname, ree_dirname_size)))
    {
        EMSG("failed calling function \'strndup\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }
    volume->ree_dirname_size = ree_dirname_size;

    res = trx_volume_import(volume, S, S_size, ibme, src, src_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_import\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }

    if (!trx_authorization_mount(auth, mount_point, S, volume->version, volume->label))
    {
        EMSG("failed calling function \'trx_authorization_mount\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_table_add(volume_table, volume);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_table_add\'");
        trx_volume_clear(volume);
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_load(volume);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_load\'");
        return TEE_ERROR_GENERIC;
    }

    res = trx_volume_table_save(volume_table);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_table_save\'");
        return TEE_ERROR_GENERIC;
    }

    DMSG("mounted volume from sender: \"%s\" with sender size: %zu and ree_dirname: \"%s\""
         "with ree_dirname_size: %zu on mount_point: \"%s\" with mount_point size: %zu",
         S, S_size, volume->ree_dirname, volume->ree_dirname_size, volume->mount_point, volume->mount_point_size);

    return res;
}