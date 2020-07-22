#ifndef TRX_TRX_DB_MAP_H
#define TRX_TRX_DB_MAP_H

#include <tee_internal_api.h>
#include <sys/queue.h>

typedef struct _db_map_entry {
    char *db_path;
    size_t db_path_size;
    SLIST_ENTRY(_db_map_entry) _db_map_entries;
} db_map_entry;
typedef SLIST_HEAD(_db_map_list_head, _db_map_entry) db_map_list_head;

void trx_db_map_list_init(db_map_list_head *h);
void trx_db_map_list_clear(db_map_list_head *h);
size_t trx_db_map_list_len(db_map_list_head *h);
int trx_db_map_list_add(char *db_path, size_t db_path_size, db_map_list_head *h);
int trx_db_map_list_snprint(char *s, size_t n, db_map_list_head *h);
int trx_db_map_list_set_str(char *s, size_t n, db_map_list_head *h);

#endif //TRX_TRX_DB_MAP_H
