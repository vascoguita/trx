#include <tee_internal_api.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/queue.h>
#include "trx_volume.h"
#include "trx_volume_table.h"
#include "trx_utils.h"

trx_volume_table *trx_volume_table_init(void)
{
    trx_volume_table *volume_table;

    DMSG("initializing volume_table");

    if (!(volume_table = malloc(sizeof(trx_volume_table))))
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    SLIST_INIT(&(volume_table->h));
    volume_table->len = 0;
    volume_table->next_volume_ree_dirname_n = 0;

    DMSG("initialized volume_table");
    return volume_table;
}

void trx_volume_table_clear(trx_volume_table *volume_table)
{
    volume_entry *e;

    DMSG("clearing volume_table");

    if (volume_table)
    {
        while (!SLIST_EMPTY(&(volume_table->h)))
        {
            e = SLIST_FIRST(&(volume_table->h));
            SLIST_REMOVE_HEAD(&(volume_table->h), _volume_entries);
            trx_volume_clear(e->volume);
            free(e);
        }
    }
    free(volume_table);

    DMSG("cleared volume_table");
}

char *trx_volume_table_gen_ree_dirname(trx_volume_table *volume_table)
{
    static char dname[PATH_MAX];

    DMSG("generating ree_dirname for volume");

    if (!snprintf(dname, PATH_MAX, trx_volume_ree_dirname_fmt, volume_table->next_volume_ree_dirname_n))
    {
        EMSG("failed calling function \'snprintf\'");
        return NULL;
    }
    volume_table->next_volume_ree_dirname_n++;

    DMSG("generated ree_dirname for volume: \"%s\"", dname);
    return dname;
}

TEE_Result trx_volume_table_add(trx_volume_table *volume_table, trx_volume *volume)
{
    volume_entry *e;

    DMSG("adding volume to volume_table");

    if (!(e = malloc(sizeof(struct _volume_entry))))
    {
        EMSG("failed calling function \'malloc\'");
        return TEE_ERROR_GENERIC;
    }
    e->volume = volume;
    SLIST_INSERT_HEAD(&(volume_table->h), e, _volume_entries);
    volume_table->len++;

    DMSG("added volume to volume_table, number of volumes: %d", (int)volume_table->len);
    return TEE_SUCCESS;
}

trx_volume *trx_volume_table_get(trx_volume_table *volume_table, char *mount_point, size_t mount_point_size)
{
    volume_entry *e;

    DMSG("getting volume from volume_table, mount_point: \"%s\", mount_point_size: %zu", mount_point, mount_point_size);

    SLIST_FOREACH(e, &(volume_table->h), _volume_entries)
    {
        if (e->volume->mount_point_size == mount_point_size)
        {
            if (memcmp(e->volume->mount_point, mount_point, mount_point_size) == 0)
            {
                DMSG("got volume from volume_table, mount_point: \"%s\", mount_point_size: %zu", mount_point, mount_point_size);
                return e->volume;
            }
        }
    }
    DMSG("did not get volume from volume_table, mount_point: \"%s\", mount_point_size: %zu", mount_point, mount_point_size);
    return NULL;
}

TEE_Result trx_volume_table_save(trx_volume_table *volume_table)
{
    uint8_t *id = NULL, *data = NULL;
    size_t data_size, id_size;
    TEE_Result res;
    uint32_t flags;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;

    DMSG("saving volume_table");

    res = trx_volume_table_serialize(volume_table, data, &data_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        EMSG("failed calling function \'trx_volume_table_serialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(data = malloc(data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_volume_table_serialize(volume_table, data, &data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_table_serialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    id_size = strlen(trx_volume_table_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    TEE_MemMove(id, trx_volume_table_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags,
                                     TEE_HANDLE_NULL, data, data_size, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_CreatePersistentObject\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("saved volume_table");
out:
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    TEE_Free(id);
    free(data);
    return res;
}

TEE_Result trx_volume_table_load(trx_volume_table *volume_table)
{
    uint8_t *id = NULL, *data = NULL;
    TEE_Result res;
    uint32_t flags, count;
    size_t id_size;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_ObjectInfo obj_info;

    DMSG("loading volume_table");

    id_size = strlen(trx_volume_table_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    TEE_MemMove(id, trx_volume_table_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_OpenPersistentObject\'");
        goto out;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'TEE_GetObjectInfo1\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(data = malloc(obj_info.dataSize)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = TEE_ReadObjectData(obj, data, obj_info.dataSize, &count);
    if (res != TEE_SUCCESS || count != obj_info.dataSize)
    {
        EMSG("failed calling function \'TEE_ReadObjectData\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_volume_table_deserialize(volume_table, data, obj_info.dataSize);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_table_deserialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("loaded volume_table");

out:
    free(data);
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    TEE_Free(id);
    return res;
}

bool trx_volume_table_exists(void)
{
    uint8_t *id = NULL;
    TEE_Result res;
    uint32_t flags;
    size_t id_size;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    bool ret;

    DMSG("checking if volume_table exists");

    id_size = strlen(trx_volume_table_id) + 1;
    if (!(id = TEE_Malloc(id_size, 0)))
    {
        EMSG("failed calling function \'TEE_Malloc\'");
        ret = false;
        goto out;
    }
    TEE_MemMove(id, trx_volume_table_id, id_size);

    flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_size, flags, &obj);
    if (res != TEE_SUCCESS)
    {
        DMSG("volume_table does not exist");
        ret = false;
        goto out;
    }
    ret = true;

    DMSG("volume_table exists");

out:
    if (obj != TEE_HANDLE_NULL)
    {
        TEE_CloseObject(obj);
    }
    TEE_Free(id);

    return ret;
}

TEE_Result trx_volume_table_serialize(trx_volume_table *volume_table, void *data, size_t *data_size)
{
    TEE_Result res;
    size_t exp_dst_size;
    uint8_t *cpy_ptr;
    uint32_t tmp_size;
    volume_entry *e;

    DMSG("checking required buffer size to serialize volume table");

    if (!volume_table)
    {
        EMSG("failed checking if volume_table is not NULL");
        return TEE_ERROR_GENERIC;
    }

    exp_dst_size = sizeof(uint8_t);
    SLIST_FOREACH(e, &(volume_table->h), _volume_entries)
    {
        exp_dst_size += sizeof(size_t);
        exp_dst_size += e->volume->mount_point_size;
        exp_dst_size += sizeof(size_t);
        exp_dst_size += e->volume->ree_dirname_size;
        exp_dst_size += trx_vk_size;
        exp_dst_size += sizeof(long unsigned int);
    }
    exp_dst_size += sizeof(unsigned long int);

    if (!data)
    {
        *data_size = exp_dst_size;
        DMSG("defining required buffer size to serialize volume table: %zu", *data_size);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*data_size != exp_dst_size)
    {
        EMSG("failed checking size of \"data\" buffer, provided_size: %zu, required_size: %zu", *data_size, exp_dst_size);
        return TEE_ERROR_GENERIC;
    }

    DMSG("serializing volume table");

    cpy_ptr = data;
    memcpy(cpy_ptr, &(volume_table->len), sizeof(uint8_t));
    cpy_ptr += sizeof(uint8_t);
    SLIST_FOREACH(e, &(volume_table->h), _volume_entries)
    {
        memcpy(cpy_ptr, &(e->volume->mount_point_size), sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        memcpy(cpy_ptr, e->volume->mount_point, e->volume->mount_point_size);
        cpy_ptr += e->volume->mount_point_size;
        memcpy(cpy_ptr, &(e->volume->ree_dirname_size), sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        memcpy(cpy_ptr, e->volume->ree_dirname, e->volume->ree_dirname_size);
        cpy_ptr += e->volume->ree_dirname_size;
        tmp_size = trx_vk_size;
        res = trx_vk_to_bytes(e->volume->vk, cpy_ptr, &tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_vk_to_bytes\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += trx_vk_size;
        memcpy(cpy_ptr, &(e->volume->version), sizeof(long unsigned int));
        cpy_ptr += sizeof(long unsigned int);
    }
    memcpy(cpy_ptr, &(volume_table->next_volume_ree_dirname_n), sizeof(long unsigned int));
    cpy_ptr += sizeof(long unsigned int);

    DMSG("serialized volume table");
    return TEE_SUCCESS;
}

TEE_Result trx_volume_table_deserialize(trx_volume_table *volume_table, void *data, size_t data_size)
{
    TEE_Result res;
    uint8_t *cpy_ptr;
    size_t left;
    uint8_t i;
    trx_volume *volume;

    DMSG("deserializing volume table from buffer with size: %zu", data_size);

    if (!data || !volume_table || !data_size)
    {
        EMSG("failed calling checking if volume table is not NULL or \"data\" buffer is not NULL"
             "or size of \"data\" buffer is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    cpy_ptr = data;
    left = data_size;
    if (left < sizeof(uint8_t))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(&i, cpy_ptr, sizeof(uint8_t));
    cpy_ptr += sizeof(uint8_t);
    left -= sizeof(uint8_t);

    while (volume_table->len < i)
    {
        if (!(volume = trx_volume_init()))
        {
            EMSG("failed calling function \'trx_volume_init\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_volume_table_add(volume_table, volume);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_table_add\'");
            trx_volume_clear(volume);
            return TEE_ERROR_GENERIC;
        }
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&(volume->mount_point_size), cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        if (left < volume->mount_point_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        if (!(volume->mount_point = malloc(volume->mount_point_size)))
        {
            EMSG("failed calling function \'malloc\'");
            return TEE_ERROR_GENERIC;
        }
        memcpy(volume->mount_point, cpy_ptr, volume->mount_point_size);
        cpy_ptr += volume->mount_point_size;
        left -= volume->mount_point_size;
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&(volume->ree_dirname_size), cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        if (left < volume->ree_dirname_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        if (!(volume->ree_dirname = malloc(volume->ree_dirname_size)))
        {
            EMSG("failed calling function \'malloc\'");
            return TEE_ERROR_GENERIC;
        }
        memcpy(volume->ree_dirname, cpy_ptr, volume->ree_dirname_size);
        cpy_ptr += volume->ree_dirname_size;
        left -= volume->ree_dirname_size;
        if (left < trx_vk_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        res = trx_vk_from_bytes(volume->vk, cpy_ptr, trx_vk_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_vk_from_bytes\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += trx_vk_size;
        left -= trx_vk_size;
        if (left < sizeof(long unsigned int))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&(volume->version), cpy_ptr, sizeof(long unsigned int));
        cpy_ptr += sizeof(long unsigned int);
        left -= sizeof(long unsigned int);
    }
    if (left < sizeof(long unsigned int))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(&(volume_table->next_volume_ree_dirname_n), cpy_ptr, sizeof(long unsigned int));
    cpy_ptr += sizeof(long unsigned int);
    left -= sizeof(long unsigned int);

    if (left != 0)
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }

    DMSG("deserialized volume table");

    return TEE_SUCCESS;
}

TEE_Result trx_volume_table_serialize_paths(trx_volume_table *volume_table, TEE_UUID *uuid, void *data, size_t *data_size)
{
    TEE_Result res;
    size_t exp_dst_size, path_str_size;
    uint8_t *cpy_ptr;
    char *path_str;
    long unsigned int n_paths = 0;
    volume_entry *volume_e;
    pobj_entry *pobj_e;
    trx_tss *tss;

    DMSG("checking required buffer size to serialize volume table paths");

    if (!volume_table)
    {
        EMSG("failed checking if volume_table is not NULL");
        return TEE_ERROR_GENERIC;
    }

    exp_dst_size = sizeof(long unsigned int);
    SLIST_FOREACH(volume_e, &(volume_table->h), _volume_entries)
    {
        if (!trx_volume_is_loaded(volume_e->volume))
        {
            res = trx_volume_load(volume_e->volume);
            if (res != TEE_SUCCESS)
            {
                EMSG("failed calling function \'trx_volume_load\'");
                return TEE_ERROR_GENERIC;
            }
        }
        tss = trx_volume_get(volume_e->volume, uuid);
        if(tss)
        {
            SLIST_FOREACH(pobj_e, &(tss->pobj_table), _pobj_entries)
            {
                path_str = path(volume_e->volume->mount_point, pobj_e->pobj->id);
                path_str_size = strlen(path_str) + 1;
                exp_dst_size += sizeof(size_t);
                exp_dst_size += path_str_size;
            }
        }
    }

    if (!data)
    {
        *data_size = exp_dst_size;
        DMSG("defining required buffer size to serialize volume table paths: %zu", *data_size);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*data_size != exp_dst_size)
    {
        EMSG("failed checking size of \"data\" buffer, provided_size: %zu, required_size: %zu", *data_size, exp_dst_size);
        return TEE_ERROR_GENERIC;
    }

    DMSG("serializing volume table paths");

    cpy_ptr = data;
    cpy_ptr += sizeof(long unsigned int);
    SLIST_FOREACH(volume_e, &(volume_table->h), _volume_entries)
    {
        if (!trx_volume_is_loaded(volume_e->volume))
        {
            res = trx_volume_load(volume_e->volume);
            if (res != TEE_SUCCESS)
            {
                EMSG("failed calling function \'trx_volume_load\'");
                return TEE_ERROR_GENERIC;
            }
        }
        tss = trx_volume_get(volume_e->volume, uuid);
        if(tss)
        {
            SLIST_FOREACH(pobj_e, &(tss->pobj_table), _pobj_entries)
            {
                path_str = path(volume_e->volume->mount_point, pobj_e->pobj->id);
                path_str_size = strlen(path_str) + 1;
                memcpy(cpy_ptr, &path_str_size, sizeof(size_t));
                cpy_ptr += sizeof(size_t);
                memcpy(cpy_ptr, path_str, path_str_size);
                cpy_ptr += path_str_size;
                n_paths++;
            }
        }
    }
    memcpy(data, &n_paths, sizeof(long unsigned int));

    DMSG("serialized volume table paths");
    return TEE_SUCCESS;
}