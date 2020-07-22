#include "trx_db_map.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>

void trx_db_map_list_init(db_map_list_head *h)
{
    SLIST_INIT(h);
}

void trx_db_map_list_clear(db_map_list_head *h)
{
    db_map_entry *e;
    while (!SLIST_EMPTY(h)) {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _db_map_entries);
        free(e->db_path);
        free(e);
    }
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

int trx_db_map_list_add(char *db_path, size_t db_path_size, db_map_list_head *h)
{
    db_map_entry *e = malloc(sizeof(struct _db_map_entry));
    if(e == NULL) {
        return 1;
    }
    e->db_path = db_path;
    e->db_path_size = db_path_size;
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
        status = snprintf(s, n, "[");
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%zu", e->db_path_size);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, ", ");
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "%s", e->db_path);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
        status = snprintf(s + result, left, "]");
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
    size_t db_map_list_len, i, db_path_size;
    char *db_path;

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
        status = strlen("[");
        if(strncmp(s, "[", status) != 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if((db_path_size = strtoul(s + result, NULL, 0)) == 0) {
            return 0;
        }
        status = snprintf(NULL, 0, "%zu", db_path_size);
        clip_sub(&result, status, &left, n);
        status = strlen(", ");
        if(strncmp(s + result, ", ", status) != 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        db_path = strndup(s + result, db_path_size);
        if(!db_path) {
            return 0;
        }
        status = db_path_size - 1;
        clip_sub(&result, status, &left, n);
        if(trx_db_map_list_add(db_path, db_path_size, h) != 0) {
            return 0;
        }
        status = strlen("]");
        if(strncmp(s + result, "]", status) != 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int) result + status;
}