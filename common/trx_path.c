#include "trx_path.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <ree_fs_api.h>

trx_path *trx_path_init(void)
{
    trx_path *path;
    if((path = (struct _trx_path*) malloc(sizeof(struct _trx_path))) == NULL) {
        return NULL;
    }
    path->path = NULL;
    path->path_size = 0;
    path->data_size = 0;
    return path;
}

void trx_path_clear(trx_path *path)
{
    if(path) {
        free(path->path);
    }
    free(path);
}

int trx_path_snprint(char *s, size_t n, trx_path *path)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", path->path_size);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%s", path->path);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", path->data_size);
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

int trx_path_set_str(char *s, size_t n, trx_path *path)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((path->path_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", path->path_size);
    clip_sub(&result, status, &left, n);
    if((path->path = (void *)malloc(path->path_size)) == NULL) {
        return 0;
    }
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((path->path = strndup(s + result, path->path_size - 1)) == NULL){
        return 0;
    }
    status = strlen(path->path);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((path->data_size = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", path->data_size);
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }
    return (int)result + status;
}

path_list_head *trx_path_list_init(void)
{
    path_list_head *h;

    if((h = (path_list_head*) malloc(sizeof(path_list_head))) == NULL) {
        return NULL;
    }
    SLIST_INIT(h);

    return h;
}

void trx_path_list_clear(path_list_head *h)
{
    path_entry *e;
    while (!SLIST_EMPTY(h)) {
        e = SLIST_FIRST(h);
        SLIST_REMOVE_HEAD(h, _path_entries);
        trx_path_clear(e->path);
        free(e);
    }
    free(h);
}

size_t trx_path_list_len(path_list_head *h)
{
    path_entry *e;
    size_t i = 0;

    SLIST_FOREACH(e, h, _path_entries) {
        i++;
    }

    return i;
}

int trx_path_list_add(trx_path *path, path_list_head *h)
{
    path_entry *e = malloc(sizeof(struct _path_entry));
    if(e == NULL) {
        return 1;
    }
    e->path = path;
    SLIST_INSERT_HEAD(h, e, _path_entries);
    return 0;
}

int trx_path_list_snprint(char *s, size_t n, path_list_head *h) {
    path_entry *e;
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", trx_path_list_len(h));
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    SLIST_FOREACH(e, h, _path_entries) {
        status = trx_path_snprint(s + result, left, e->path);
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

int trx_path_list_set_str(char *s, size_t n, path_list_head *h) {
    size_t result, left;
    int status;
    size_t path_list_len, i;
    trx_path *path;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((path_list_len = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", path_list_len);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; i < path_list_len; i++) {
        if (!(path = trx_path_init())) {
            return 0;
        }
        if ((status = trx_path_set_str(s + result, left, path)) == 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        if (trx_path_list_add(path, h) != 0) {
            return 0;
        }
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0) {
        return 0;
    }
    return (int) result + status;
}