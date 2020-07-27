#include "trx_tss.h"
#include "trx_pobj.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

int trx_tss_init(trx_tss **tss)
{
    if((*tss = (struct _trx_tss*) malloc(sizeof(struct _trx_tss))) == NULL) {
        return 1;
    }
    if(((*tss)->uuid = (TEE_UUID*) malloc(sizeof(TEE_UUID))) == NULL) {
        free(*tss);
        return 1;
    }
    if(trx_pobj_list_init(&((*tss)->pobj_lh)) != 0){
        free((*tss)->uuid);
        free(*tss);
        return 1;
    }
    return 0;
}

void trx_tss_clear(trx_tss *tss) {
    if (tss != NULL) {
        free(tss->uuid);
        trx_pobj_list_clear(tss->pobj_lh);
        free(tss);
    }
}

int trx_tss_snprint(char *s, size_t n, trx_tss *tss)
{
    size_t result, left;
    int status, i;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%x", tss->uuid->timeLow);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", tss->uuid->timeMid);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", tss->uuid->timeHiAndVersion);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < 8; i++) {
        if((i == 0) || (i == 2)) {
            status = snprintf(s + result, left, "-%x", tss->uuid->clockSeqAndNode[i]);
        } else {
            status = snprintf(s + result, left, "%x", tss->uuid->clockSeqAndNode[i]);
        }
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
    status = trx_pobj_list_snprint(s + result, left, tss->pobj_lh);
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

int trx_tss_set_str(char *s, size_t n, trx_tss *tss)
{
    size_t result, left;
    int status;
    char uuid_tmp_str[37];

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");
    clip_sub(&result, status, &left, n);
    status = snprintf(uuid_tmp_str, 37, "%s", s + result);
    if (status < 0) {
        return 0;
    }
    status = 37 - 1;
    DMSG("\nDEBUG\n");

    DMSG("\nDEBUG, %d, \'%s\'\n", status, s + result);
    clip_sub(&result, status, &left, n);
    if(tee_uuid_from_str(tss->uuid, uuid_tmp_str) != TEE_SUCCESS) {
        return 0;
    }
    DMSG("\nDEBUG, %d, \'%s\'\n", status, s + result);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");
    clip_sub(&result, status, &left, n);
    if((status = trx_pobj_list_set_str(s + result, left, tss->pobj_lh)) == 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");

    return (int)result + status;
}

int trx_tss_list_init(tss_list_head **h)
{

    if((*h = (tss_list_head*) malloc(sizeof(tss_list_head))) == NULL) {
        return 1;
    }
    SLIST_INIT(*h);
    return 0;
}

void trx_tss_list_clear(tss_list_head *h)
{
    tss_entry *e;
    while (!SLIST_EMPTY(h)) {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _tss_entries);
        trx_tss_clear(e->tss);
        free(e);
    }
    free(h);
}

size_t trx_tss_list_len(tss_list_head *h)
{
    tss_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _tss_entries) {
        i++;
    }

    return i;
}

int trx_tss_list_add(trx_tss *tss, tss_list_head *h)
{
    tss_entry *e = malloc(sizeof(struct _tss_entry));
    if(e == NULL) {
        return 1;
    }
    e->tss = tss;
    SLIST_INSERT_HEAD(h, e, _tss_entries);
    return 0;
}

trx_tss *trx_tss_list_get(TEE_UUID *uuid, tss_list_head *h)
{
    tss_entry *e;

    SLIST_FOREACH(e, h, _tss_entries) {
        if(memcmp(e->tss->uuid, uuid, sizeof(TEE_UUID)) == 0) {
            return e->tss;
        }
    }
    return NULL;
}

int trx_tss_list_snprint(char *s, size_t n, tss_list_head *h) {
    tss_entry *e;
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_tss_list_len(h));
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    SLIST_FOREACH(e, h, _tss_entries) {
        status = trx_tss_snprint(s + result, left, e->tss);
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

int trx_tss_list_set_str(char *s, size_t n, tss_list_head *h)
{
    size_t result, left;
    int status;
    size_t tss_list_len, i;
    trx_tss *tss;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    DMSG("\nDEBUG\n");
    tss_list_len = strtoul(s + result, NULL, 0);
    status = snprintf(NULL, 0, "%zu", tss_list_len);
    clip_sub(&result, status, &left, n);
    DMSG("\nDEBUG\n");
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");
    clip_sub(&result, status, &left, n);
    for(i = 0; i < tss_list_len; i++) {
        DMSG("\nDEBUG\n");
        if(trx_tss_init(&tss) != 0) {
            return 0;
        }
        DMSG("\nDEBUG\n");
        if((status = trx_tss_set_str(s + result, left, tss)) == 0) {
            return 0;
        }
        DMSG("\nDEBUG\n");
        clip_sub(&result, status, &left, n);
        if(trx_tss_list_add(tss, h) != 0) {
            return 0;
        }
        DMSG("\nDEBUG\n");
    }
    DMSG("\nDEBUG\n");
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");

    return (int)result + status;
}