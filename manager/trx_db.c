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
    if(trx_tss_list_init(&((*db)->tss_lh)) != 0) {
        free(*db);
        return 1;
    }
    (*db)->next_ree_id = 1;
    return 0;
}

void trx_db_clear(trx_db *db)
{
    if (db != NULL) {
        trx_tss_list_clear(db->tss_lh);
        free(db);
    }
}

trx_pobj *trx_db_insert(TEE_UUID *uuid, void *id, size_t id_size, trx_db *db)
{
    trx_tss *tss;
    trx_pobj *pobj;

    if((tss = trx_tss_list_get(uuid, db->tss_lh)) == NULL) {
        trx_tss_init(&tss);
        memcpy(tss->uuid, uuid, sizeof(TEE_UUID));
        trx_tss_list_add(tss, db->tss_lh);
    }
    if(trx_pobj_init(&pobj) != 0) {
        return NULL;
    }
    if((pobj->id = (void *)malloc(id_size)) == NULL) {
        trx_pobj_clear(pobj);
        return NULL;
    }
    memcpy(pobj->id, id, id_size);
    pobj->id_size = id_size;
    pobj->ree_id = db->next_ree_id;
    if(trx_pobj_list_add(pobj, tss->pobj_lh) != 0) {
        trx_pobj_clear(pobj);
        return NULL;
    }
    db->next_ree_id++;
    return pobj;
}

trx_pobj *trx_db_get(TEE_UUID *uuid, void *id, size_t id_size, trx_db *db)
{
    trx_tss *tss;
    if((tss = trx_tss_list_get(uuid, db->tss_lh)) == NULL) {
        return NULL;
    }
    return trx_pobj_list_get(id, id_size, tss->pobj_lh);
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
    DMSG("\nDEBUG\n");
    if((db->next_ree_id = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");
    status = snprintf(NULL, 0, "%lu", db->next_ree_id);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    DMSG("\nDEBUG\n");
    if((status = trx_tss_list_set_str(s + result, left, db->tss_lh)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    DMSG("\nDEBUG\n");
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }
    DMSG("\nDEBUG\n");

    return (int)result + status;
}

int trx_db_save(trx_db *db, char *filename, size_t filename_size)
{
    int db_str_len, fd;
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

    res = ree_fs_api_create(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        free(db_str);
        return 1;
    }
    res = ree_fs_api_write(fd, 0, db_str, db_str_len + 1);
    if(res != TEE_SUCCESS) {
        ree_fs_api_close(fd);
        free(db_str);
        return 1;
    }
    ree_fs_api_close(fd);
    free(db_str);
    return 0;
}

int trx_db_load(trx_db *db, char *filename, size_t filename_size)
{
    //FIXME allocate memory to the size of the db file
    size_t db_str_size = 200;
    char *db_str;
    int fd;
    TEE_Result res;

    DMSG("\nDEBUG\n");
    res = ree_fs_api_open(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        return 1;
    }
    DMSG("\nDEBUG\n");
    if((db_str = (char *)malloc(db_str_size * sizeof(char))) == NULL){
        ree_fs_api_close(fd);
        return 1;
    }
    DMSG("\nDEBUG\n");
    res = ree_fs_api_read(fd, 0, db_str, &db_str_size);
    if(res != TEE_SUCCESS) {
        free(db_str);
        ree_fs_api_close(fd);
        return 1;
    }
    DMSG("\nDEBUG\n");
    ree_fs_api_close(fd);
    DMSG("\nDEBUG\n");
    DMSG("\n\'%s\', %zu\n", db_str, db_str_size);
    if(trx_db_set_str(db_str, db_str_size, db) == 0) {
        free(db_str);
        return 1;
    }
    DMSG("\nDEBUG\n");
    free(db_str);
    return 0;
}