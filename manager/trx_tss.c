#include "trx_tss.h"
#include "trx_pobj.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

trx_tss *trx_tss_init(void)
{
    trx_tss *tss;

    DMSG("initializing tss");

    if (!(tss = (struct _trx_tss *)malloc(sizeof(struct _trx_tss))))
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    if (!(tss->uuid = (TEE_UUID *)malloc(sizeof(TEE_UUID))))
    {
        EMSG("failed calling function \'malloc\'");
        trx_tss_clear(tss);
        return NULL;
    }
    SLIST_INIT(&(tss->pobj_table));
    tss->pobj_table_len = 0;

    DMSG("initialized tss");

    return tss;
}

void trx_tss_clear(trx_tss *tss)
{
    pobj_entry *e;

    DMSG("clearing tss");

    if (tss)
    {
        while (!SLIST_EMPTY(&(tss->pobj_table)))
        {
            e = SLIST_FIRST(&(tss->pobj_table));
            SLIST_REMOVE_HEAD(&(tss->pobj_table), _pobj_entries);
            trx_pobj_clear(e->pobj);
            free(e);
        }
        free(tss->uuid);
    }
    free(tss);

    DMSG("cleared tss");
}

trx_tss *trx_tss_create(TEE_UUID *uuid)
{
    trx_tss *tss;

    DMSG("creating tss");

    if (!(tss = trx_tss_init()))
    {
        EMSG("failed calling function \'trx_tss_init\'");
        return NULL;
    }
    memcpy(tss->uuid, uuid, sizeof(TEE_UUID));

    DMSG("created tss");
    return tss;
}

TEE_Result trx_tss_add(trx_tss *tss, trx_pobj *pobj)
{
    pobj_entry *e;
    TEE_Result res;

    DMSG("adding pobj to tss");

    if (!(e = malloc(sizeof(struct _pobj_entry))))
    {
        EMSG("failed calling function \'malloc\'");
        return TEE_ERROR_GENERIC;
    }
    e->pobj = pobj;

    res = trx_pobj_set_tss(pobj, tss);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_tss\'");
        return TEE_ERROR_GENERIC;
    }

    SLIST_INSERT_HEAD(&(tss->pobj_table), e, _pobj_entries);
    tss->pobj_table_len++;

    DMSG("added pobj to tss, number of pobjs: %lu", tss->pobj_table_len);

    return TEE_SUCCESS;
}

trx_pobj *trx_tss_get(trx_tss *tss, const char *id, size_t id_size)
{
    pobj_entry *e;

    DMSG("getting pobj from tss, id: \"%s\", id_size: %zu", id, id_size);

    SLIST_FOREACH(e, &(tss->pobj_table), _pobj_entries)
    {
        if ((e->pobj->id_size == id_size) && (strncmp(e->pobj->id, id, id_size) == 0))
        {
            DMSG("got pobj from tss, id: \"%s\", id_size: %zu", id, id_size);
            return e->pobj;
        }
    }

    DMSG("did not get pobj from tss, id: \"%s\", id_size: %zu", id, id_size);

    return NULL;
}

TEE_Result trx_tss_serialize(trx_tss *tss, void *data, size_t *data_size)
{
    size_t exp_dst_size;
    uint8_t *cpy_ptr;
    pobj_entry *e;

    DMSG("checking required buffer size to serialize tss");

    if (!tss)
    {
        EMSG("failed checking if tss is not NULL");
        return TEE_ERROR_GENERIC;
    }

    exp_dst_size = sizeof(long unsigned int);
    SLIST_FOREACH(e, &(tss->pobj_table), _pobj_entries)
    {
        exp_dst_size += sizeof(size_t);
        exp_dst_size += e->pobj->id_size;
        exp_dst_size += sizeof(size_t);
        exp_dst_size += e->pobj->ree_basename_size;
        exp_dst_size += sizeof(long unsigned int);
        exp_dst_size += sizeof(size_t);
    }
    exp_dst_size += sizeof(TEE_UUID);

    if (!data)
    {
        *data_size = exp_dst_size;
        DMSG("defining required buffer size to serialize tss: %zu", *data_size);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*data_size != exp_dst_size)
    {
        EMSG("failed checking size of \"data\" buffer, provided_size: %zu, required_size: %zu", *data_size, exp_dst_size);
        return TEE_ERROR_GENERIC;
    }

    cpy_ptr = data;
    memcpy(cpy_ptr, &(tss->pobj_table_len), sizeof(long unsigned int));
    cpy_ptr += sizeof(long unsigned int);
    SLIST_FOREACH(e, &(tss->pobj_table), _pobj_entries)
    {
        memcpy(cpy_ptr, &(e->pobj->id_size), sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        memcpy(cpy_ptr, e->pobj->id, e->pobj->id_size);
        cpy_ptr += e->pobj->id_size;
        memcpy(cpy_ptr, &(e->pobj->ree_basename_size), sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        memcpy(cpy_ptr, e->pobj->ree_basename, e->pobj->ree_basename_size);
        cpy_ptr += e->pobj->ree_basename_size;
        memcpy(cpy_ptr, &(e->pobj->version), sizeof(long unsigned int));
        cpy_ptr += sizeof(long unsigned int);
        memcpy(cpy_ptr, &(e->pobj->data_size), sizeof(size_t));
        cpy_ptr += sizeof(size_t);
    }
    memcpy(cpy_ptr, tss->uuid, sizeof(TEE_UUID));
    cpy_ptr += sizeof(TEE_UUID);

    DMSG("serialized tss");

    return TEE_SUCCESS;
}

TEE_Result trx_tss_deserialize(trx_tss *tss, void *data, size_t data_size)
{
    TEE_Result res;
    uint8_t *cpy_ptr;
    size_t left, tmp_size;
    long unsigned int i, tmp_version;
    trx_pobj *pobj;

    DMSG("deserializing tss from buffer with size: %zu", data_size);

    if (!data || !tss || !data_size)
    {
        EMSG("failed calling checking if volume table is not NULL or \"data\" buffer is not NULL"
             "or size of \"data\" buffer is greater than 1");
        return TEE_ERROR_GENERIC;
    }

    cpy_ptr = data;
    left = data_size;
    if (left < sizeof(long unsigned int))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(&i, cpy_ptr, sizeof(long unsigned int));
    cpy_ptr += sizeof(long unsigned int);
    left -= sizeof(long unsigned int);

    while (tss->pobj_table_len < i)
    {
        if (!(pobj = trx_pobj_init()))
        {
            EMSG("failed calling function \'trx_pobj_init\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_tss_add(tss, pobj);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_tss_add\'");
            trx_pobj_clear(pobj);
            return TEE_ERROR_GENERIC;
        }
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&tmp_size, cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        if (left < tmp_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        res = trx_pobj_set_id(pobj, (char *)cpy_ptr, tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_id\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += tmp_size;
        left -= tmp_size;
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&tmp_size, cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        if (left < tmp_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        res = trx_pobj_set_ree_basename(pobj, (char *)cpy_ptr, tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_ree_basename\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += tmp_size;
        left -= tmp_size;
        if (left < sizeof(long unsigned int))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&tmp_version, cpy_ptr, sizeof(long unsigned int));
        res = trx_pobj_set_version(pobj, tmp_version);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_version\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += sizeof(long unsigned int);
        left -= sizeof(long unsigned int);
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&tmp_size, cpy_ptr, sizeof(size_t));
        res = trx_pobj_set_data_size(pobj, tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_data_size\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);
    }
    if (left < sizeof(TEE_UUID))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(tss->uuid, cpy_ptr, sizeof(TEE_UUID));
    cpy_ptr += sizeof(TEE_UUID);
    left -= sizeof(TEE_UUID);

    if (left != 0)
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }

    DMSG("deserialized tss");

    return TEE_SUCCESS;
}