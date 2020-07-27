#include "trx_db_map.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>

int trx_db_map_init(trx_db_map **db_map)
{
    if((*db_map = (struct _trx_db_map*) malloc(sizeof(struct _trx_db_map))) == NULL) {
        return 1;
    }
    (*db_map)->path = NULL;
    (*db_map)->path_size = 0;
    return 0;
}

void trx_db_map_clear(trx_db_map *db_map)
{
    if(db_map != NULL) {
        free(db_map->path);
        free(db_map);
    }
}

int trx_db_map_snprint(char *s, size_t n, trx_db_map *db_map)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", db_map->path_size);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", db_map->path);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int trx_db_map_set_str(char *s, size_t n, trx_db_map *db_map)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((db_map->path_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", db_map->path_size);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((db_map->path = strndup(s + result, db_map->path_size - 1)) == NULL){
        return 0;
    }
    status = db_map->path_size - 1;
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

TEE_Result trx_db_map_save(trx_db_map *db_map, const char *tmp_id, size_t id_size)
{
    int db_map_str_len;
    char *db_map_str, *id;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj;

    if((db_map_str_len = trx_db_map_snprint(NULL, 0, db_map)) < 1) {
        return TEE_ERROR_GENERIC;
    }
    if((db_map_str = (char *) malloc((db_map_str_len + 1) * sizeof(char))) == NULL) {
        return TEE_ERROR_GENERIC;
    }
    if(db_map_str_len != trx_db_map_snprint(db_map_str, (db_map_str_len + 1) , db_map)) {
        free(db_map_str);
        return TEE_ERROR_GENERIC;
    }

    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, tmp_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ |	TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
            TEE_HANDLE_NULL, db_map_str, db_map_str_len + 1, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
    }
    TEE_Free(id);
    TEE_CloseObject(obj);
    free(db_map_str);
    return res;
}

TEE_Result trx_db_map_load(trx_db_map *db_map, const char *tmp_id, size_t id_size)
{
    char *db_map_str, *id;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj;
    TEE_ObjectInfo obj_info;

    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, tmp_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(id);
        return res;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        TEE_CloseObject(obj);
        TEE_Free(id);
        return res;
    }

    if((db_map_str = (char*) malloc(obj_info.dataSize)) == NULL) {
        TEE_CloseObject(obj);
        TEE_Free(id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    res = TEE_ReadObjectData(obj, db_map_str, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize) {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, count, obj_info.dataSize);
        TEE_CloseObject(obj);
        TEE_Free(id);
        free(db_map_str);
        return res;
    }
    TEE_CloseObject(obj);
    TEE_Free(id);

    if(trx_db_map_set_str(db_map_str, obj_info.dataSize, db_map) == 0) {
        res = TEE_ERROR_GENERIC;
    }

    free(db_map_str);
    return res;
}

int trx_db_map_list_init(db_map_list_head **h)
{
    if((*h = (db_map_list_head*) malloc(sizeof(db_map_list_head))) == NULL) {
        return 1;
    }
    SLIST_INIT(*h);
    return 0;
}

void trx_db_map_list_clear(db_map_list_head *h)
{
    db_map_entry *e;
    while (!SLIST_EMPTY(h)) {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _db_map_entries);
        trx_db_map_clear(e->db_map);
        free(e);
    }
    free(h);
}

size_t trx_db_map_list_len(db_map_list_head *h)
{
    db_map_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _db_map_entries) {
        i++;
    }

    return i;
}

int trx_db_map_list_add(trx_db_map *db_map, db_map_list_head *h)
{
    db_map_entry *e = malloc(sizeof(struct _db_map_entry));
    if(e == NULL) {
        return 1;
    }
    e->db_map = db_map;
    SLIST_INSERT_HEAD(h, e, _db_map_entries);
    return 0;
}

int trx_db_map_list_snprint(char *s, size_t n, db_map_list_head *h) {
    db_map_entry *e;
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_db_map_list_len(h));
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    SLIST_FOREACH(e, h, _db_map_entries) {
        status = trx_db_map_snprint(s + result, left, e->db_map);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int trx_db_map_list_set_str(char *s, size_t n, db_map_list_head *h) {
    size_t result, left;
    int status;
    size_t db_map_list_len, i;
    trx_db_map *db_map;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((db_map_list_len = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", db_map_list_len);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; i < db_map_list_len; i++) {
        if(trx_db_map_init(&db_map) != 0) {
            return 0;
        }
        if((status = trx_db_map_set_str(s + result, left, db_map)) == 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if(trx_db_map_list_add(db_map, h) != 0) {
            return 0;
        }
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int) result + status;
}

TEE_Result trx_db_map_list_save(db_map_list_head *h, const char *tmp_id, size_t id_size)
{
    int db_map_list_str_len;
    char *db_map_list_str, *id;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj;

    if((db_map_list_str_len = trx_db_map_list_snprint(NULL, 0, h)) < 1) {
        return TEE_ERROR_GENERIC;
    }
    if((db_map_list_str = (char *) malloc((db_map_list_str_len + 1) * sizeof(char))) == NULL) {
        return TEE_ERROR_GENERIC;
    }
    if(db_map_list_str_len != trx_db_map_list_snprint(db_map_list_str, (db_map_list_str_len + 1) , h)) {
        free(db_map_list_str);
        return TEE_ERROR_GENERIC;
    }

    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, tmp_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ |	TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, TEE_HANDLE_NULL, db_map_list_str, db_map_list_str_len + 1, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
    }
    TEE_Free(id);
    TEE_CloseObject(obj);
    free(db_map_list_str);
    return res;
}

TEE_Result trx_db_map_list_load(db_map_list_head *h, const char *tmp_id, size_t id_size)
{
    char *db_map_list_str, *id;
    TEE_Result res;
    uint32_t flags, count;
    TEE_ObjectHandle obj;
    TEE_ObjectInfo obj_info;

    if(!(id = TEE_Malloc(id_size, 0))) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(id, tmp_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(id);
        return res;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        TEE_CloseObject(obj);
        TEE_Free(id);
        return res;
    }

    if((db_map_list_str = (char*) malloc(obj_info.dataSize)) == NULL) {
        TEE_CloseObject(obj);
        TEE_Free(id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    res = TEE_ReadObjectData(obj, db_map_list_str, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize) {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, count, obj_info.dataSize);
        TEE_CloseObject(obj);
        TEE_Free(id);
        free(db_map_list_str);
        return res;
    }
    TEE_CloseObject(obj);
    TEE_Free(id);

    if(trx_db_map_list_set_str(db_map_list_str, obj_info.dataSize, h) == 0) {
        res = TEE_ERROR_GENERIC;
    }

    free(db_map_list_str);
    return res;
}