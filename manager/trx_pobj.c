#include "trx_pobj.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <ree_fs_api.h>
#include <utee_defines.h>
#include "trx_db.h"
#include "trx_file.h"

trx_pobj *trx_pobj_init(void)
{
    trx_pobj *pobj;
    if ((pobj = (struct _trx_pobj *)malloc(sizeof(struct _trx_pobj))) == NULL)
    {
        return NULL;
    }
    if (!(pobj->file = trx_file_init()))
    {
        trx_pobj_clear(pobj);
        return NULL;
    }
    pobj->file->pobj = pobj;
    pobj->id = NULL;
    pobj->id_size = 0;
    pobj->tss = NULL;
    pobj->data = NULL;
    pobj->data_size = 0;
    return pobj;
}

void trx_pobj_clear(trx_pobj *pobj)
{
    if (pobj)
    {
        free(pobj->id);
        free(pobj->data);
        trx_file_clear(pobj->file);
    }
    free(pobj);
}

int trx_pobj_save(trx_pobj *pobj)
{
    TEE_Result res;

    res = trx_file_encrypt(pobj->file);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }

    if (trx_file_save(pobj->file))
    {
        return 1;
    }

    return 0;
}

int trx_pobj_load(trx_pobj *pobj)
{
    TEE_Result res;

    if (trx_file_load(pobj->file))
    {
        return 1;
    }

    res = trx_file_decrypt(pobj->file);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }
    return 0;
}

int trx_pobj_snprint(char *s, size_t n, trx_pobj *pobj)
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
    status = snprintf(s + result, left, "%zu", pobj->id_size);
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
    status = snprintf(s + result, left, "%s", pobj->id);
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
    status = snprintf(s + result, left, "%zu", pobj->file->ree_basename_size);
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
    status = snprintf(s + result, left, "%s", pobj->file->ree_basename);
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
    status = snprintf(s + result, left, "%10zu", pobj->data_size);
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

int trx_pobj_set_str(char *s, size_t n, trx_pobj *pobj)
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
    if ((pobj->id_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj->id_size);
    clip_sub(&result, status, &left, n);
    if ((pobj->id = (void *)malloc(pobj->id_size)) == NULL)
    {
        return 0;
    }
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj->id = strndup(s + result, pobj->id_size - 1)) == NULL)
    {
        return 0;
    }
    status = strlen(pobj->id);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj->file->ree_basename_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj->file->ree_basename_size);
    clip_sub(&result, status, &left, n);
    if ((pobj->file->ree_basename = (void *)malloc(pobj->file->ree_basename_size)) == NULL)
    {
        return 0;
    }
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj->file->ree_basename = strndup(s + result, pobj->file->ree_basename_size - 1)) == NULL)
    {
        return 0;
    }
    status = strlen(pobj->file->ree_basename);
    clip_sub(&result, status, &left, n);

    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj->data_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%10zu", pobj->data_size);
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }
    return (int)result + status;
}

pobj_list_head *trx_pobj_list_init(void)
{
    pobj_list_head *h;

    if ((h = (pobj_list_head *)malloc(sizeof(pobj_list_head))) == NULL)
    {
        return NULL;
    }
    SLIST_INIT(h);

    return h;
}

void trx_pobj_list_clear(pobj_list_head *h)
{
    pobj_entry *e;
    while (!SLIST_EMPTY(h))
    {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _pobj_entries);
        trx_pobj_clear(e->pobj);
        free(e);
    }
    free(h);
}

size_t trx_pobj_list_len(pobj_list_head *h)
{
    pobj_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _pobj_entries)
    {
        i++;
    }

    return i;
}

trx_pobj *trx_pobj_list_get(const char *id, size_t id_size, pobj_list_head *h)
{
    pobj_entry *e;

    SLIST_FOREACH(e, h, _pobj_entries)
    {
        if ((e->pobj->id_size == id_size) && (strncmp(e->pobj->id, id, id_size) == 0))
        {
            return e->pobj;
        }
    }
    return NULL;
}

int trx_pobj_list_add(trx_pobj *pobj, pobj_list_head *h)
{
    pobj_entry *e = malloc(sizeof(struct _pobj_entry));
    if (e == NULL)
    {
        return 1;
    }
    e->pobj = pobj;
    SLIST_INSERT_HEAD(h, e, _pobj_entries);
    return 0;
}

int trx_pobj_list_snprint(char *s, size_t n, pobj_list_head *h)
{
    pobj_entry *e;
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_pobj_list_len(h));
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
    SLIST_FOREACH(e, h, _pobj_entries)
    {
        status = trx_pobj_snprint(s + result, left, e->pobj);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int trx_pobj_list_set_str(char *s, size_t n, pobj_list_head *h)
{
    size_t result, left;
    int status;
    size_t pobj_list_len, i;
    trx_pobj *pobj;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj_list_len = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj_list_len);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; i < pobj_list_len; i++)
    {
        if (!(pobj = trx_pobj_init()))
        {
            return 0;
        }
        if ((status = trx_pobj_set_str(s + result, left, pobj)) == 0)
        {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if (trx_pobj_list_add(pobj, h) != 0)
        {
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