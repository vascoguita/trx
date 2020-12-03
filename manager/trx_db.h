#ifndef TRX_TRX_DB_H
#define TRX_TRX_DB_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_tss.h"
#include "trx_pobj.h"
#include "trx_file.h"
#include "trx_path.h"
#include "trx_manager_defaults.h"

struct _path_list_head;
struct _tss_list_head;
struct _trx_pobj;
struct _trx_file;
struct _trx_path;

typedef struct _trx_db
{
    struct _tss_list_head *tss_lh;
    char *next_ree_basename;
    size_t next_ree_basename_size;
    char *mount_point;
    size_t mount_point_size;
    char *ree_dirname;
    size_t ree_dirname_size;
    struct _trx_pobj *pobj;
    TEE_ObjectHandle bk;
} trx_db;

trx_db *trx_db_init(void);
void trx_db_clear(trx_db *db);
struct _trx_pobj *trx_db_insert(const TEE_UUID *uuid, const char *id, size_t id_size, trx_db *db);
struct _trx_pobj *trx_db_get(TEE_UUID *uuid, const char *id, size_t id_size, trx_db *db);
int trx_db_snprint(char *s, size_t n, trx_db *db);
int trx_db_set_str(char *s, size_t n, trx_db *db);
int trx_db_gen_ree_basename(trx_db *db, struct _trx_file *file);

int trx_db_save(trx_db *db);
int trx_db_load(trx_db *db);

typedef struct _db_entry
{
    trx_db *db;
    SLIST_ENTRY(_db_entry)
    _db_entries;
} db_entry;
typedef SLIST_HEAD(_db_list_head, _db_entry) db_list_head;

db_list_head *trx_db_list_init(void);
void trx_db_list_clear(db_list_head *h);
size_t trx_db_list_len(db_list_head *h);
int trx_db_list_add(trx_db *db, db_list_head *h);
trx_db *trx_db_list_get(char *mount_point, size_t mount_point_size, db_list_head *h);
TEE_Result trx_db_list_save(db_list_head *h);
TEE_Result trx_db_list_load(db_list_head *h);
int trx_db_list_snprint(char *s, size_t n, db_list_head *h);
int trx_db_list_set_str(char *s, size_t n, db_list_head *h);
int trx_db_list_to_path_list(struct _path_list_head *path_lh, TEE_UUID *uuid, db_list_head *db_lh);

struct _trx_pobj *trx_db_list_insert_pobj(TEE_UUID *uuid, char *path, size_t path_size, db_list_head *h);
struct _trx_pobj *trx_db_list_get_pobj(TEE_UUID *uuid, char *path, size_t path_size, db_list_head *h);

#endif //TRX_TRX_DB_H
