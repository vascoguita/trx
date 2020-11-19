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
#include "trx_db.h"
#include "trx_ibme.h"
#include "trx_file.h"
#include <ibme/ibme.h>
#include <tui/tui.h>

TEE_Result setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    char *param_str, *mpk_str, *ek_str, *dk_str;
    size_t param_str_size, mpk_str_size, ek_str_size, dk_str_size;
    trx_db *db;
    db_list_head *db_lh;
    trx_ibme *ibme;
    TEE_Result res;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    if (param_types != exp_param_types)
    {
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
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_ibme_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (!(ibme->param_str = strndup(param_str, param_str_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'strndup\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    ibme->param_str_size = param_str_size;
    if (1 == pairing_init_set_str(*(ibme->pairing), ibme->param_str))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'pairing_init_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (1 == MPK_init(*(ibme->pairing), &(ibme->mpk)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'MPK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (1 == EK_init(*(ibme->pairing), &(ibme->ek)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'EK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (1 == DK_init(*(ibme->pairing), &(ibme->dk)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'DK_init\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == MPK_set_str(mpk_str, mpk_str_size, ibme->mpk))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'MPK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == EK_set_str(ek_str, ek_str_size, ibme->ek))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'EK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    if (0 == DK_set_str(dk_str, dk_str_size, ibme->dk))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'DK_set_str\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    res = trx_ibme_save(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_ibme_save\'");
        trx_ibme_clear(ibme);
        return TEE_ERROR_GENERIC;
    }
    trx_ibme_clear(ibme);
    if (!(db = trx_db_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (!(db->mount_point = strdup(dirname(NULL))))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'strdup\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    res = TEE_GenerateKey(db->bk, HMACSHA256_KEY_BIT_SIZE, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, HMACSHA256_KEY_BIT_SIZE, res);
        trx_db_clear(db);
        return res;
    }
    db->mount_point_size = strlen(db->mount_point) + 1;
    db->ree_dirname = strndup(DEFAULT_REE_DIRNAME, DEFAULT_REE_DIRNAME_SIZE);
    db->ree_dirname_size = DEFAULT_REE_DIRNAME_SIZE;

    if (trx_db_save(db) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_save\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_init\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    if (trx_db_list_add(db, db_lh) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_add\'");
        trx_db_clear(db);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    res = trx_db_list_save(db_lh);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SETUP failed calling function \'trx_db_list_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    trx_db_list_clear(db_lh);

    return res;
}

TEE_Result write(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
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
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = params[1].memref.size;

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x", res);
        return res;
    }
    uuid = &identity.uuid;

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (trx_db_list_load(db_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if ((pobj = trx_db_list_get_pobj(uuid, path, path_size, db_lh)) == NULL)
    {
        if ((pobj = trx_db_list_insert_pobj(uuid, path, path_size, db_lh)) == NULL)
        {
            EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_list_insert_pobj\'");
            trx_db_list_clear(db_lh);
            return TEE_ERROR_GENERIC;
        }
    }

    pobj->data_size = data_size;
    pobj->data = malloc(data_size);
    memcpy(pobj->data, data, data_size);
    if (trx_db_save(pobj->tss->db) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_db_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if (trx_pobj_save(pobj) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_WRITE failed calling function \'trx_pobj_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result read(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
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
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    path = params[0].memref.buffer;
    path_size = params[0].memref.size;
    data = params[1].memref.buffer;
    data_size = &(params[1].memref.size);

    res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
    if (res != TEE_SUCCESS)
    {
        EMSG("TRX Manager failed to retrieve client identity, res=0x%08x", res);
        return res;
    }
    uuid = &identity.uuid;

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (trx_db_list_load(db_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if ((pobj = trx_db_list_get_pobj(uuid, path, path_size, db_lh)) == NULL)
    {
        EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_db_list_get_pobj\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if ((*data_size > (uint32_t)pobj->data_size) || (*data_size == 0))
    {
        *data_size = (uint32_t)pobj->data_size;
    }
    if (data != NULL)
    {
        if (trx_pobj_load(pobj) != 0)
        {
            EMSG("TA_TRX_MANAGER_CMD_READ failed calling function \'trx_pobj_load\'");
            trx_db_list_clear(db_lh);
            return TEE_ERROR_GENERIC;
        }
        memcpy(data, pobj->data, (size_t)*data_size);
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result list(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
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

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }

    if (trx_db_list_load(db_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if (!(path_lh = trx_path_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_path_list_init\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if (trx_db_list_to_path_list(path_lh, uuid, db_lh) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_LIST failed calling function \'trx_db_list_to_path_list\'");
        trx_db_list_clear(db_lh);
        trx_path_list_clear(path_lh);
        return TEE_ERROR_GENERIC;
    }

    if ((tmp_list_size = trx_path_list_snprint(list, *list_size, path_lh) + 1) < 1)
    {
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
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    uint32_t exp_param_types, buffer_size;
    char *S, *ree_dirname, *mount_point, *auth_msg;
    size_t S_size, ree_dirname_size, mount_point_size, tmp_size, input_size, auth_msg_size;
    trx_db *db;
    db_list_head *db_lh;
    trx_pobj *pobj;
    trx_ibme *ibme;
    Cipher *bk_enc;
    TEE_Result res;
    uint8_t buffer[HMACSHA256_KEY_SIZE];
    TEE_Attribute attr = {};
    char input[100];

    (void)&sess_ctx;

    input_size = 100;
    buffer_size = HMACSHA256_KEY_SIZE;

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

    if (!(db = trx_db_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_db_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (!(db->mount_point = strndup(mount_point, mount_point_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'strdup\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    db->mount_point_size = mount_point_size;
    db->ree_dirname = strndup(ree_dirname, ree_dirname_size);
    db->ree_dirname_size = ree_dirname_size;

    if (!(pobj = trx_db_insert(&uuid, DEFAULT_DB_ID, strlen(DEFAULT_DB_ID) + 1, db)))
    {
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (!(pobj->file->ree_basename = strdup("0")))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'strdup\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    pobj->file->ree_basename_size = strlen(pobj->file->ree_basename) + 1;

    if (trx_file_load(pobj->file))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_file_load\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_ibme_init\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_ibme_load\'");
        trx_ibme_clear(ibme);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (1 == Cipher_init(*(ibme->pairing), &bk_enc))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'Cipher_init\'");
        trx_ibme_clear(ibme);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (0 == Cipher_set_str(pobj->file->bk_enc, pobj->file->bk_enc_size, bk_enc))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'Cipher_set_str\'");
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    tmp_size = buffer_size;
    if (ibme_dec(*(ibme->pairing), ibme->dk, (unsigned char *)S, S_size, bk_enc, (unsigned char *)buffer, &tmp_size) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed to decrypt the cipher using sender identity \"%s\".", S);
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    Cipher_clear(bk_enc);
    trx_ibme_clear(ibme);

    if ((auth_msg_size = snprintf(NULL, 0, "Authorize Secure Storage Volume from \"%s\" to be mounted on "
                                           "\"%s\"? [y\\n] ",
                                  S, mount_point) +
                         1) < 1)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'snprintf\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (!(auth_msg = malloc(auth_msg_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'malloc\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (auth_msg_size != ((size_t)snprintf(auth_msg, auth_msg_size, "Authorize Secure Storage Volume from \"%s\" to be mounted on "
                                                                    "\"%s\"? [y\\n] ",
                                           S, mount_point) +
                          1))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'snprintf\'");
        DMSG("\"%s\"\n%zu", auth_msg, auth_msg_size);
        free(auth_msg);
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    res = TUI->input(auth_msg, input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT Failed to input with code 0x%x", res);
        free(auth_msg);
        trx_db_clear(db);
        return res;
    }
    free(auth_msg);
    if (strncmp(input, "y", strlen("y")) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT not authorized by user");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
    res = TEE_PopulateTransientObject(db->bk, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'TEE_PopulateTransientObject\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_db_list_init\'");
        trx_db_clear(db);
        return TEE_ERROR_GENERIC;
    }
    if (trx_db_list_load(db_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (trx_db_list_add(db, db_lh) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_db_list_add\'");
        trx_db_clear(db);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    res = trx_db_list_save(db_lh);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT failed calling function \'trx_db_list_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_db_list_clear(db_lh);
    return res;
}

TEE_Result share(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, buffer_size;
    TEE_Result res;
    char *R, *mount_point, *auth_msg;
    size_t R_size, mount_point_size, auth_msg_size, input_size;
    db_list_head *db_lh;
    trx_db *db;
    trx_ibme *ibme;
    Cipher *bk_enc;
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    trx_pobj *pobj;
    uint8_t buffer[HMACSHA256_KEY_SIZE];
    char input[100];

    input_size = 100;
    buffer_size = HMACSHA256_KEY_SIZE;

    (void)&sess_ctx;

    DMSG("has been called");

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

    if (!(db_lh = trx_db_list_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_db_list_init\'");
        return TEE_ERROR_GENERIC;
    }
    if (trx_db_list_load(db_lh) != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_db_list_load\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if ((db = trx_db_list_get(mount_point, mount_point_size, db_lh)) == NULL)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_db_list_get\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    res = TEE_GetObjectBufferAttribute(db->bk, TEE_ATTR_SECRET_VALUE, buffer, &buffer_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'TEE_GetObjectBufferAttribute\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_ibme_init\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_ibme_load\'");
        trx_ibme_clear(ibme);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (1 == Cipher_init(*(ibme->pairing), &bk_enc))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'Cipher_init\'");
        trx_ibme_clear(ibme);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (1 == ibme_enc(*(ibme->pairing), ibme->mpk, ibme->ek, (unsigned char *)R, R_size, buffer, buffer_size, bk_enc))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'ibme_enc\'");
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_ibme_clear(ibme);

    if (trx_db_load(db) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_db_load\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (!(pobj = trx_db_get(&uuid, DEFAULT_DB_ID, strlen(DEFAULT_DB_ID) + 1, db)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_db_get\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (trx_file_load(pobj->file))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_file_load\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if ((pobj->file->bk_enc_size = Cipher_snprint(NULL, 0, bk_enc) + 1) < 1)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'Cipher_snprint\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (!(pobj->file->bk_enc = malloc(pobj->file->bk_enc_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'malloc\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (pobj->file->bk_enc_size != (size_t)(Cipher_snprint(pobj->file->bk_enc, pobj->file->bk_enc_size, bk_enc) + 1))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'Cipher_snprint\'");
        Cipher_clear(bk_enc);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    Cipher_clear(bk_enc);

    DMSG("Authorize Secure Storage Volume mounted on "
         "\"%s\" to be shared with \"%s\"? [y\\n] ",
         mount_point, R);
    if ((auth_msg_size = snprintf(NULL, 0, "Authorize Secure Storage Volume mounted on "
                                           "\"%s\" to be shared with \"%s\"? [y\\n] ",
                                  mount_point, R) +
                         1) < 1)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'snprintf\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (!(auth_msg = malloc(auth_msg_size)))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'malloc\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    if (auth_msg_size != ((size_t)snprintf(auth_msg, auth_msg_size, "Authorize Secure Storage Volume mounted on "
                                                                    "\"%s\" to be shared with \"%s\"? [y\\n] ",
                                           mount_point, R) +
                          1))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'snprintf\'");
        DMSG("\"%s\"\n%zu", auth_msg, auth_msg_size);
        free(auth_msg);
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    res = TUI->input(auth_msg, input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE Failed to input with code 0x%x", res);
        free(auth_msg);
        trx_db_list_clear(db_lh);
        return res;
    }
    free(auth_msg);
    if (strncmp(input, "y", strlen("y")) != 0)
    {
        EMSG("TA_TRX_MANAGER_CMD_MOUNT not authorized by user");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }

    if (trx_file_save(pobj->file))
    {
        EMSG("TA_TRX_MANAGER_CMD_SHARE failed calling function \'trx_file_save\'");
        trx_db_list_clear(db_lh);
        return TEE_ERROR_GENERIC;
    }
    trx_db_list_clear(db_lh);
    return TEE_SUCCESS;
}