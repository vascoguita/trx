#include "trx_db.h"
#include "trx_tss.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <ree_fs_api.h>

int trx_db_init(trx_db **db)
{
    if((*db = (struct _trx_db*) malloc(sizeof(struct _trx_db))) == NULL) {
        return 1;
    }
    if(((*db)->tss_lh = (tss_list_head*) malloc(sizeof(tss_list_head))) == NULL) {
        free(*db);
        return 1;
    }
    trx_tss_list_init((*db)->tss_lh);
    (*db)->next_ree_id = 0;
    return 0;
}

void trx_db_clear(trx_db *db) {
    if (db != NULL) {
        trx_tss_list_clear(db->tss_lh);
        free(db);
    }
}

int trx_db_snprint(char *s, size_t n, trx_db *db)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%lu", db->next_ree_id);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = trx_tss_list_snprint(s + result, left, db->tss_lh);
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

int trx_db_set_str(char *s, size_t n, trx_db *db)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((db->next_ree_id = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", db->next_ree_id);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = trx_tss_list_set_str(s + result, left, db->tss_lh);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int trx_db_out_str(trx_db *db, int fd)
{
    int db_str_len;
    char *db_str;
    TEE_Result res;

    if((db_str_len = trx_db_snprint(NULL, 0, db)) < 1) {
        return 1;
    }

    if((db_str = (char *) malloc((db_str_len + 1) * sizeof(char))) == NULL) {
        return 1;
    }

    if(db_str_len != trx_db_snprint(db_str, (db_str_len + 1) , db)) {
        free(db_str);
        return 1;
    }

    res = ree_fs_api_write(fd, 0, db_str, db_str_len + 1);
    if(res != TEE_SUCCESS) {
        free(db_str);
        return 1;
    }

    free(db_str);
    return 0;
}