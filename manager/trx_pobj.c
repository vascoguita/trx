#include "trx_pobj.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

int trx_pobj_init(trx_pobj **pobj)
{
    if((*pobj = (struct _trx_pobj*) malloc(sizeof(struct _trx_pobj))) == NULL) {
        return 1;
    }
    (*pobj)->id = NULL;
    (*pobj)->id_size = 0;
    (*pobj)->ree_id = 0;
    return 0;
}

void trx_pobj_clear(trx_pobj *pobj)
{
    if(pobj != NULL) {
        free(pobj->id);
        free(pobj);
    }
}

int trx_pobj_snprint(char *s, size_t n, trx_pobj *pobj)
{
    size_t result, left, i;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", pobj->id_size);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < pobj->id_size; i++) {
        status = snprintf(s + result, left, "\\x%x", ((uint8_t*)pobj->id)[i]);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", pobj->ree_id);
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

int trx_pobj_set_str(char *s, size_t n, trx_pobj *pobj)
{
    size_t result, left;
    int status;
    size_t i;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((pobj->id_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj->id_size);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < pobj->id_size; i++) {
        status = strlen("\\x");
        if(strncmp(s + result, "\\x", status) != 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        ((uint8_t*)pobj->id)[i] = strtoul(s + result, NULL, 16);
        status = snprintf(NULL, 0, "%x", ((uint8_t*)pobj->id)[i]);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((pobj->ree_id = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj->ree_id);
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

void trx_pobj_list_init(pobj_list_head *h)
{
    SLIST_INIT(h);
}

void trx_pobj_list_clear(pobj_list_head *h)
{
    pobj_entry *e;
    while (!SLIST_EMPTY(h)) {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _pobj_entries);
        trx_pobj_clear(e->pobj);
        free(e);
    }
}

size_t trx_pobj_list_len(pobj_list_head *h)
{
    pobj_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _pobj_entries) {
        i++;
    }

    return i;
}

int trx_pobj_list_add(trx_pobj *pobj, pobj_list_head *h)
{
    pobj_entry *e = malloc(sizeof(struct _pobj_entry));
    if(e == NULL) {
        return 1;
    }
    e->pobj = pobj;
    SLIST_INSERT_HEAD(h, e, _pobj_entries);
    return 0;
}


int trx_pobj_list_snprint(char *s, size_t n, pobj_list_head *h) {
    pobj_entry *e;
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_pobj_list_len(h));
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    SLIST_FOREACH(e, h, _pobj_entries) {
        status = trx_pobj_snprint(s + result, left, e->pobj);
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

int trx_pobj_list_set_str(char *s, size_t n, pobj_list_head *h) {
    size_t result, left;
    int status;
    size_t pobj_list_len, i;
    trx_pobj *pobj;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((pobj_list_len = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", pobj_list_len);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; i < pobj_list_len; i++) {
        if (trx_pobj_init(&pobj) != 0) {
            return 0;
        }
        if ((status = trx_pobj_set_str(s + result, left, pobj)) == 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if (trx_pobj_list_add(pobj, h) != 0) {
            return 0;
        }
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int) result + status;
}