#ifndef TRX_TRX_DB_MAP_H
#define TRX_TRX_DB_MAP_H

#include <tee_internal_api.h>
#include <sys/queue.h>

typedef struct _trx_db_map {
    char *path;
    size_t path_size;
} trx_db_map;

int trx_db_map_init(trx_db_map **db_map);
void trx_db_map_clear(trx_db_map *db_map);
int trx_db_map_snprint(char *s, size_t n, trx_db_map *db_map);
int trx_db_map_set_str(char *s, size_t n, trx_db_map *db_map);

TEE_Result trx_db_map_save(trx_db_map *db_map, const char *tmp_id, size_t id_size);
TEE_Result trx_db_map_load(trx_db_map *db_map, const char *tmp_id, size_t id_size);

typedef struct _db_map_entry {
    trx_db_map *db_map;
    SLIST_ENTRY(_db_map_entry) _db_map_entries;
} db_map_entry;
typedef SLIST_HEAD(_db_map_list_head, _db_map_entry) db_map_list_head;

int trx_db_map_list_init(db_map_list_head **h);
void trx_db_map_list_clear(db_map_list_head *h);
size_t trx_db_map_list_len(db_map_list_head *h);
int trx_db_map_list_add(trx_db_map *db_map, db_map_list_head *h);
int trx_db_map_list_snprint(char *s, size_t n, db_map_list_head *h);
int trx_db_map_list_set_str(char *s, size_t n, db_map_list_head *h);

TEE_Result trx_db_map_list_save(db_map_list_head *h, const char *id, size_t id_size);
TEE_Result trx_db_map_list_load(db_map_list_head *h, const char *id, size_t id_size);

#endif //TRX_TRX_DB_MAP_H
