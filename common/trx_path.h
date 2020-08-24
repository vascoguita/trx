#ifndef TRX_TRX_PATH_H
#define TRX_TRX_PATH_H

#include <tee_internal_api.h>
#include <sys/queue.h>

typedef struct _trx_path {
    char *path;
    size_t path_size;
    size_t data_size;
} trx_path;

trx_path *trx_path_init(void);
void trx_path_clear(trx_path *path);

int trx_path_snprint(char *s, size_t n, trx_path *path);
int trx_path_set_str(char *s, size_t n, trx_path *path);

typedef struct _path_entry {
    trx_path *path;
    SLIST_ENTRY(_path_entry) _path_entries;
} path_entry;
typedef SLIST_HEAD(_path_list_head, _path_entry) path_list_head;

path_list_head *trx_path_list_init(void);
void trx_path_list_clear(path_list_head *h);
int trx_path_list_add(trx_path *path, path_list_head *h);
size_t trx_path_list_len(path_list_head *h);
int trx_path_list_snprint(char *s, size_t n, path_list_head *h);
int trx_path_list_set_str(char *s, size_t n, path_list_head *h);

#endif //TRX_TRX_PATH_H