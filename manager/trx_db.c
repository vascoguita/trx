#include "trx_db.h"
#include "trx_tss.h"
#include "trx_path.h"
#include "trx_ibme.h"
#include "utils.h"
#include "trx_manager_ta.h"
#include "trx_manager_defaults.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <ree_fs_api.h>

trx_db *trx_db_init(void)
{
    trx_db *db;
    if ((db = (struct _trx_db *)malloc(sizeof(struct _trx_db))) == NULL)
    {
        return NULL;
    }
    if (!(db->tss_lh = trx_tss_list_init()))
    {
        trx_db_clear(db);
        return NULL;
    }
    if (TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, HMACSHA256_KEY_BIT_SIZE, &(db->bk)) != TEE_SUCCESS)
    {
        trx_db_clear(db);
        return NULL;
    }
    db->next_ree_basename = strdup("0");
    db->next_ree_basename_size = strlen(db->next_ree_basename) + 1;
    db->mount_point = NULL;
    db->mount_point_size = 0;
    db->ree_dirname = NULL;
    db->ree_dirname_size = 0;
    return db;
}

void trx_db_clear(trx_db *db)
{
    if (db)
    {
        trx_tss_list_clear(db->tss_lh);
        free(db->next_ree_basename);
        free(db->mount_point);
        free(db->ree_dirname);
        TEE_FreeTransientObject(db->bk);
    }
    free(db);
}

int trx_db_gen_ree_basename(trx_db *db, trx_file *file)
{
    unsigned long int next_ree_basename_n;

    if (!(file->ree_basename = strndup(db->next_ree_basename, db->next_ree_basename_size)))
    {
        return 1;
    }
    file->ree_basename_size = db->next_ree_basename_size;

    next_ree_basename_n = strtoul(db->next_ree_basename, NULL, 10) + 1;

    if ((db->next_ree_basename_size = snprintf(NULL, 0, "%lu", next_ree_basename_n) + 1) < 1)
    {
        return 1;
    }

    if (!(db->next_ree_basename = realloc(db->next_ree_basename, db->next_ree_basename_size)))
    {
        return 1;
    }

    if (db->next_ree_basename_size != (size_t)(snprintf(db->next_ree_basename, db->next_ree_basename_size, "%lu", next_ree_basename_n) + 1))
    {
        return 1;
    }

    return 0;
}

trx_pobj *trx_db_insert(const TEE_UUID *uuid, const char *id, size_t id_size, trx_db *db)
{
    trx_tss *tss;
    trx_pobj *pobj;

    if (!(tss = trx_tss_list_get(uuid, db->tss_lh)))
    {
        if (!(tss = trx_tss_init()))
        {
            return NULL;
        }
        memcpy(tss->uuid, uuid, sizeof(TEE_UUID));
        tss->db = db;
        if (trx_tss_list_add(tss, db->tss_lh) != 0)
        {
            trx_tss_clear(tss);
            return NULL;
        }
    }

    if (!(pobj = trx_pobj_init()))
    {
        return NULL;
    }

    if (trx_db_gen_ree_basename(db, pobj->file) != 0)
    {
        trx_pobj_clear(pobj);
        return NULL;
    }

    pobj->tss = tss;

    if (!(pobj->id = strndup(id, id_size)))
    {
        trx_pobj_clear(pobj);
        return NULL;
    }

    pobj->id_size = strlen(pobj->id) + 1;
    if (trx_pobj_list_add(pobj, tss->pobj_lh) != 0)
    {
        trx_pobj_clear(pobj);
        return NULL;
    }

    return pobj;
}

trx_pobj *trx_db_get(TEE_UUID *uuid, const char *id, size_t id_size, trx_db *db)
{
    trx_tss *tss;
    trx_pobj *pobj;
    if ((tss = trx_tss_list_get(uuid, db->tss_lh)) == NULL)
    {
        return NULL;
    }
    tss->db = db;
    if ((pobj = trx_pobj_list_get(id, id_size, tss->pobj_lh)) == NULL)
    {
        return NULL;
    }
    pobj->tss = tss;
    return pobj;
}

int trx_db_snprint(char *s, size_t n, trx_db *db)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", db->next_ree_basename_size);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", db->next_ree_basename);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = trx_tss_list_snprint(s + result, left, db->tss_lh);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int trx_db_set_str(char *s, size_t n, trx_db *db)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((db->next_ree_basename_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", db->next_ree_basename_size);
    clip_sub(&result, status, &left, n);
    if ((db->next_ree_basename = (void *)malloc(db->next_ree_basename_size)) == NULL)
    {
        return 0;
    }
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((db->next_ree_basename = strndup(s + result, db->next_ree_basename_size - 1)) == NULL)
    {
        return 0;
    }
    status = strlen(db->next_ree_basename);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = trx_tss_list_set_str(s + result, left, db->tss_lh)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

int trx_db_save(trx_db *db)
{
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    trx_pobj *pobj;

    if (!(pobj = trx_db_get(&uuid, DEFAULT_DB_ID, DEFAULT_DB_ID_SIZE, db)))
    {
        if (!(pobj = trx_db_insert(&uuid, DEFAULT_DB_ID, DEFAULT_DB_ID_SIZE, db)))
        {
            return 1;
        }
    }
    if ((pobj->data_size = trx_db_snprint(NULL, 0, db) + 1) < 1)
    {
        return 1;
    }
    if ((pobj->data = (char *)malloc(pobj->data_size)) == NULL)
    {
        return 1;
    }
    if (pobj->data_size != ((size_t)trx_db_snprint((char *)pobj->data, pobj->data_size, db) + 1))
    {
        return 1;
    }
    if (trx_pobj_save(pobj) != 0)
    {
        return 1;
    }
    return 0;
}

int trx_db_load(trx_db *db)
{
    trx_pobj *pobj, *pobj2;
    trx_tss *tss;
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;

    if (!(tss = trx_tss_init()))
    {
        return 1;
    }

    memcpy(tss->uuid, &uuid, sizeof(TEE_UUID));
    tss->db = db;

    if (!(pobj = trx_pobj_init()))
    {
        trx_tss_clear(tss);
        return 1;
    }

    if (trx_pobj_list_add(pobj, tss->pobj_lh) != 0)
    {
        trx_pobj_clear(pobj);
        trx_tss_clear(tss);
        return 1;
    }

    pobj->tss = tss;

    if (!(pobj->file->ree_basename = strdup("0")))
    {
        trx_tss_clear(tss);
        return 1;
    }

    pobj->file->ree_basename_size = strlen(pobj->file->ree_basename) + 1;
    if (trx_pobj_load(pobj) != 0)
    {
        trx_tss_clear(tss);
        return 1;
    }

    if (trx_db_set_str(pobj->data, pobj->data_size, db) == 0)
    {
        trx_tss_clear(tss);
        return 1;
    }

    if (pobj->file->bk_enc && pobj->file->bk_enc_size)
    {

        if (!(pobj2 = trx_db_get(&uuid, DEFAULT_DB_ID, DEFAULT_DB_ID_SIZE, db)))
        {
            trx_tss_clear(tss);
            return 1;
        }

        pobj2->file->bk_enc_size = pobj->file->bk_enc_size;
        free(pobj2->file->bk_enc);

        if (!(pobj2->file->bk_enc = malloc(pobj2->file->bk_enc_size)))
        {
            trx_tss_clear(tss);
            return 1;
        }

        memcpy(pobj2->file->bk_enc, pobj->file->bk_enc, pobj2->file->bk_enc_size);
    }

    trx_tss_clear(tss);
    return 0;
}

int trx_db_share(trx_db *db, char *R, size_t R_size)
{
    TEE_Result res;
    uint32_t buffer_size;
    trx_ibme *ibme;
    Cipher *bk_enc;
    trx_pobj *pobj;
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    uint8_t buffer[HMACSHA256_KEY_SIZE];

    buffer_size = HMACSHA256_KEY_SIZE;

    res = TEE_GetObjectBufferAttribute(db->bk, TEE_ATTR_SECRET_VALUE, buffer, &buffer_size);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }

    if (!(ibme = trx_ibme_init()))
    {
        return 1;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        trx_ibme_clear(ibme);
        return 1;
    }
    if (!(bk_enc = Cipher_init(*(ibme->pairing))))
    {
        trx_ibme_clear(ibme);
        return 1;
    }
    if (1 == ibme_enc(*(ibme->pairing), ibme->mpk, ibme->ek, (unsigned char *)R, R_size, buffer, buffer_size, bk_enc))
    {
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        return 1;
    }
    trx_ibme_clear(ibme);

    if (trx_db_load(db) != 0)
    {
        Cipher_clear(bk_enc);
        return 1;
    }
    if (!(pobj = trx_db_get(&uuid, DEFAULT_DB_ID, strlen(DEFAULT_DB_ID) + 1, db)))
    {
        Cipher_clear(bk_enc);
        return 1;
    }
    if (trx_file_load(pobj->file))
    {
        Cipher_clear(bk_enc);
        return 1;
    }

    if ((pobj->file->bk_enc_size = Cipher_snprint(NULL, 0, bk_enc) + 1) < 1)
    {
        Cipher_clear(bk_enc);
        return 1;
    }
    if (!(pobj->file->bk_enc = malloc(pobj->file->bk_enc_size)))
    {
        Cipher_clear(bk_enc);
        return 1;
    }
    if (pobj->file->bk_enc_size != (size_t)(Cipher_snprint(pobj->file->bk_enc, pobj->file->bk_enc_size, bk_enc) + 1))
    {
        Cipher_clear(bk_enc);
        return 1;
    }
    Cipher_clear(bk_enc);

    if (trx_file_save(pobj->file))
    {
        return 1;
    }

    return 0;
}

int trx_db_import(trx_db *db, char *S, size_t S_size)
{   
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;
    uint32_t buffer_size;
    size_t tmp_size;
    trx_pobj *pobj;
    trx_ibme *ibme;
    Cipher *bk_enc;
    TEE_Result res;
    uint8_t buffer[HMACSHA256_KEY_SIZE];
    TEE_Attribute attr = {};

    buffer_size = HMACSHA256_KEY_SIZE;
    
    if (!(pobj = trx_db_insert(&uuid, DEFAULT_DB_ID, strlen(DEFAULT_DB_ID) + 1, db)))
    {
        return 1;
    }
    if (!(pobj->file->ree_basename = strdup("0")))
    {
        return 1;
    }
    pobj->file->ree_basename_size = strlen(pobj->file->ree_basename) + 1;

    if (trx_file_load(pobj->file))
    {
        return 1;
    }

    if (!(ibme = trx_ibme_init()))
    {
        return 1;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        trx_ibme_clear(ibme);
        return 1;
    }
    if (!(bk_enc = Cipher_init(*(ibme->pairing))))
    {
        trx_ibme_clear(ibme);
        return 1;
    }
    if (0 == Cipher_set_str(pobj->file->bk_enc, pobj->file->bk_enc_size, bk_enc))
    {
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        return 1;
    }

    tmp_size = buffer_size;
    if (ibme_dec(*(ibme->pairing), ibme->dk, (unsigned char *)S, S_size, bk_enc, (unsigned char *)buffer, &tmp_size) != 0)
    {
        Cipher_clear(bk_enc);
        trx_ibme_clear(ibme);
        return 1;
    }
    Cipher_clear(bk_enc);
    trx_ibme_clear(ibme);

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
    res = TEE_PopulateTransientObject(db->bk, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }
    return 0;
}

db_list_head *trx_db_list_init(void)
{
    db_list_head *h;
    if ((h = (db_list_head *)malloc(sizeof(db_list_head))) == NULL)
    {
        return NULL;
    }
    SLIST_INIT(h);
    return h;
}

void trx_db_list_clear(db_list_head *h)
{
    db_entry *e;
    while (!SLIST_EMPTY(h))
    {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _db_entries);
        trx_db_clear(e->db);
        free(e);
    }
    free(h);
}

size_t trx_db_list_len(db_list_head *h)
{
    db_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _db_entries)
    {
        i++;
    }

    return i;
}

int trx_db_list_add(trx_db *db, db_list_head *h)
{
    db_entry *e = malloc(sizeof(struct _db_entry));
    if (e == NULL)
    {
        return 1;
    }
    e->db = db;
    SLIST_INSERT_HEAD(h, e, _db_entries);
    return 0;
}

int trx_db_list_snprint(char *s, size_t n, db_list_head *h)
{
    db_entry *e;
    size_t result, left;
    int status;
    TEE_Result res;
    uint32_t buffer_size, i;
    uint8_t buffer[HMACSHA256_KEY_SIZE];

    buffer_size = HMACSHA256_KEY_SIZE;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_db_list_len(h));
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    SLIST_FOREACH(e, h, _db_entries)
    {
        status = snprintf(s + result, left, ", ");
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%zu", e->db->mount_point_size);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, ", ");
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%s", e->db->mount_point);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, ", ");
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%zu", e->db->ree_dirname_size);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, ", ");
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%s", e->db->ree_dirname);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, ", ");
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
        res = TEE_GetObjectBufferAttribute(e->db->bk, TEE_ATTR_SECRET_VALUE, buffer, &buffer_size);
        if (res != TEE_SUCCESS)
        {
            return status;
        }
        for (i = 0; i < buffer_size; i++)
        {
            status = snprintf(s + result, left, "%02x ", buffer[i]);
            if (status < 0)
            {
                return status;
            }
            clip_sub(&result, status, &left, n);
        }
    }
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int trx_db_list_set_str(char *s, size_t n, db_list_head *h)
{
    size_t result, left;
    int status;
    size_t db_list_len, i;
    trx_db *db;
    uint32_t buffer_size, j;
    uint8_t buffer[HMACSHA256_KEY_SIZE];
    TEE_Result res;
    TEE_Attribute attr = {};

    buffer_size = HMACSHA256_KEY_SIZE;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((db_list_len = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", db_list_len);
    clip_sub(&result, status, &left, n);
    for (i = 0; i < db_list_len; i++)
    {
        status = strlen(", ");
        if (strncmp(s + result, ", ", status) != 0)
        {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if (!(db = trx_db_init()))
        {
            return 0;
        }
        db->mount_point_size = strtoul(s + result, NULL, 0);
        status = snprintf(NULL, 0, "%zu", db->mount_point_size);
        clip_sub(&result, status, &left, n);
        status = strlen(", ");
        if (strncmp(s + result, ", ", status) != 0)
        {
            trx_db_clear(db);
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if ((db->mount_point = strndup(s + result, db->mount_point_size - 1)) == NULL)
        {
            trx_db_clear(db);
            return 0;
        }
        status = db->mount_point_size - 1;
        clip_sub(&result, status, &left, n);
        status = strlen(", ");
        if (strncmp(s + result, ", ", status) != 0)
        {
            trx_db_clear(db);
            return 0;
        }
        clip_sub(&result, status, &left, n);
        db->ree_dirname_size = strtoul(s + result, NULL, 0);
        status = snprintf(NULL, 0, "%zu", db->ree_dirname_size);
        clip_sub(&result, status, &left, n);
        status = strlen(", ");
        if (strncmp(s + result, ", ", status) != 0)
        {
            trx_db_clear(db);
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if ((db->ree_dirname = strndup(s + result, db->ree_dirname_size - 1)) == NULL)
        {
            trx_db_clear(db);
            return 0;
        }
        status = db->ree_dirname_size - 1;
        clip_sub(&result, status, &left, n);
        status = strlen(", ");
        if (strncmp(s + result, ", ", status) != 0)
        {
            trx_db_clear(db);
            return 0;
        }
        clip_sub(&result, status, &left, n);
        for (j = 0; j < buffer_size; j++)
        {
            buffer[j] = strtoul(s + result, NULL, 16);
            status = snprintf(NULL, 0, "%02x ", buffer[j]);
            if (status < 0)
            {
                return status;
            }
            clip_sub(&result, status, &left, n);
        }
        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, buffer, buffer_size);
        res = TEE_PopulateTransientObject(db->bk, &attr, 1);
        if (res != TEE_SUCCESS)
        {
            return status;
        }
        if (trx_db_list_add(db, h) != 0)
        {
            trx_db_clear(db);
            return 0;
        }
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

TEE_Result trx_db_list_save(db_list_head *h)
{
    int db_list_str_len, id_size;
    char *db_list_str, *id;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj;

    if ((db_list_str_len = trx_db_list_snprint(NULL, 0, h)) < 1)
    {
        return TEE_ERROR_GENERIC;
    }
    if ((db_list_str = (char *)malloc((db_list_str_len + 1) * sizeof(char))) == NULL)
    {
        return TEE_ERROR_GENERIC;
    }
    if (db_list_str_len != trx_db_list_snprint(db_list_str, (db_list_str_len + 1), h))
    {
        free(db_list_str);
        return TEE_ERROR_GENERIC;
    }

    id_size = strlen(DEFAULT_DB_LIST_ID) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, DEFAULT_DB_LIST_ID, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
                                     TEE_HANDLE_NULL, db_list_str, db_list_str_len + 1, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
    }
    TEE_Free(id);
    TEE_CloseObject(obj);
    free(db_list_str);
    return res;
}

TEE_Result trx_db_list_load(db_list_head *h)
{
    int id_size;
    char *db_list_str, *id;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj;
    TEE_ObjectInfo obj_info;
    id_size = strlen(DEFAULT_DB_LIST_ID) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, DEFAULT_DB_LIST_ID, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(id);
        return res;
    }
    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        TEE_CloseObject(obj);
        TEE_Free(id);
        return res;
    }
    if ((db_list_str = (char *)malloc(obj_info.dataSize)) == NULL)
    {
        TEE_CloseObject(obj);
        TEE_Free(id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    res = TEE_ReadObjectData(obj, db_list_str, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize)
    {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 "over %u", res, count, obj_info.dataSize);
        TEE_CloseObject(obj);
        TEE_Free(id);
        free(db_list_str);
        return res;
    }
    TEE_CloseObject(obj);
    TEE_Free(id);

    if (trx_db_list_set_str(db_list_str, obj_info.dataSize, h) == 0)
    {
        res = TEE_ERROR_GENERIC;
    }

    free(db_list_str);
    return res;
}

trx_pobj *trx_db_list_insert_pobj(TEE_UUID *uuid, char *path, size_t path_size, db_list_head *h)
{
    trx_db *db;
    char *mount_point, *id;
    size_t mount_point_size, id_size;
    TEE_UUID manager_uuid = TA_TRX_MANAGER_UUID;

    (void)&path_size;

    if (!(mount_point = dirname(path)))
    {
        return NULL;
    }

    mount_point_size = strlen(mount_point) + 1;
    if (!(db = trx_db_list_get(mount_point, mount_point_size, h)))
    {
        return NULL;
    }

    if (!(id = basename(path)))
    {
        return NULL;
    }

    id_size = strlen(id) + 1;
    //FIXME

    if (trx_db_get(&manager_uuid, DEFAULT_DB_ID, DEFAULT_DB_ID_SIZE, db) == NULL)
    {

        if (trx_db_load(db) != 0)
        {
            return NULL;
        }
    }

    return trx_db_insert(uuid, id, id_size, db);
}

trx_pobj *trx_db_list_get_pobj(TEE_UUID *uuid, char *path, size_t path_size, db_list_head *h)
{
    trx_db *db;
    char *mount_point, *id;
    size_t mount_point_size, id_size;
    trx_pobj *pobj;
    TEE_UUID manager_uuid = TA_TRX_MANAGER_UUID;

    (void)&path_size;

    if (!(mount_point = dirname(path)))
    {
        return NULL;
    }
    mount_point_size = strlen(mount_point) + 1;
    if (!(db = trx_db_list_get(mount_point, mount_point_size, h)))
    {
        return NULL;
    }
    if (!(id = basename(path)))
    {
        return NULL;
    }
    id_size = strlen(id) + 1;
    //FIXME
    if (trx_db_get(&manager_uuid, DEFAULT_DB_ID, DEFAULT_DB_ID_SIZE, db) == NULL)
    {

        if (trx_db_load(db) != 0)
        {
            return NULL;
        }
    }
    if (!(pobj = trx_db_get(uuid, id, id_size, db)))
    {
        return NULL;
    }
    return pobj;
}

trx_db *trx_db_list_get(char *mount_point, size_t mount_point_size, db_list_head *h)
{
    db_entry *e;

    SLIST_FOREACH(e, h, _db_entries)
    {
        if (e->db->mount_point_size == mount_point_size)
        {
            if (memcmp(e->db->mount_point, mount_point, mount_point_size) == 0)
            {
                //if(trx_db_get(&uuid, DEFAULT_DB_ID, strlen(DEFAULT_DB_ID) + 1, e->db) == NULL) {
                //    if (trx_db_load(e->db) != 0) {
                //        return NULL;
                //    }
                //}
                return e->db;
            }
        }
    }
    return NULL;
}

int trx_db_list_to_path_list(struct _path_list_head *path_lh, TEE_UUID *uuid, db_list_head *db_lh)
{
    db_entry *db_e;
    trx_tss *tss;
    pobj_entry *pobj_e;
    struct _trx_path *path;

    SLIST_FOREACH(db_e, db_lh, _db_entries)
    {
        if (trx_db_load(db_e->db) != 0)
        {
            return 1;
        }
        if ((tss = trx_tss_list_get(uuid, db_e->db->tss_lh)))
        {
            SLIST_FOREACH(pobj_e, tss->pobj_lh, _pobj_entries)
            {
                if (!(path = trx_path_init()))
                {
                    return 1;
                }
                if ((path->path_size = snprintf(NULL, 0, "%s/%s", db_e->db->mount_point, pobj_e->pobj->id) + 1) < 1)
                {
                    trx_path_clear(path);
                    return 1;
                }
                if (!(path->path = malloc(path->path_size)))
                {
                    trx_path_clear(path);
                    return 1;
                }
                if (path->path_size != (size_t)(snprintf(path->path, path->path_size, "%s/%s", db_e->db->mount_point, pobj_e->pobj->id) + 1))
                {
                    trx_path_clear(path);
                    return 1;
                }
                path->data_size = pobj_e->pobj->data_size;
                if (trx_path_list_add(path, path_lh) != 0)
                {
                    trx_path_clear(path);
                    return 1;
                }
            }
        }
    }
    return 0;
}