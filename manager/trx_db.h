#ifndef TRX_TRX_DB_H
#define TRX_TRX_DB_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_tss.h"

typedef struct _trx_db {
    unsigned long next_ree_id;
    tss_list_head *tss_lh;
} trx_db;

int trx_db_init(trx_db **db);
void trx_db_clear(trx_db *db);
trx_pobj *trx_db_insert(TEE_UUID *uuid, void *id, size_t id_size, trx_db *db);
trx_pobj *trx_db_get(TEE_UUID *uuid, void *id, size_t id_size, trx_db *db);
int trx_db_snprint(char *s, size_t n, trx_db *db);
int trx_db_set_str(char *s, size_t n, trx_db *db);

int trx_db_save(trx_db *db, char *filename, size_t filename_size);
int trx_db_load(trx_db *db, char *filename, size_t filename_size);

#endif //TRX_TRX_DB_H
