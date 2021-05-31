#ifndef TRX_TRX_VOLUME_H
#define TRX_TRX_VOLUME_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_tss.h"
#include "trx_keys.h"
#include "trx_ibme.h"

struct _trx_tss;

typedef struct _tss_entry
{
    struct _trx_tss *tss;
    SLIST_ENTRY(_tss_entry)
    _tss_entries;
} tss_entry;
typedef SLIST_HEAD(_tss_table_head, _tss_entry) tss_table_head;

typedef struct _trx_volume
{
    tss_table_head tss_table;
    long unsigned int tss_table_len;
    unsigned long int next_pobj_ree_basename_n;
    char *mount_point;
    size_t mount_point_size;
    char *ree_dirname;
    size_t ree_dirname_size;
    void *udid;
    size_t udid_size;
    char *label;
    size_t label_size;
    unsigned long int version;
    trx_vk *vk;
    bool isloaded;
    size_t file_size;
} trx_volume;

trx_volume *trx_volume_init(void);
void trx_volume_clear(trx_volume *volume);
trx_volume *trx_volume_create(char *mount_point, size_t mount_point_size, char *ree_dirname, size_t ree_dirname_size,
                              void *udid, size_t udid_size);
TEE_Result trx_volume_set_udid(trx_volume *volume, void *udid, size_t udid_size);
TEE_Result trx_volume_set_label(trx_volume *volume, char *label, size_t label_size);
TEE_Result trx_volume_set_file_size(trx_volume *volume, size_t file_size);
TEE_Result trx_volume_add(trx_volume *volume, struct _trx_tss *tss);
struct _trx_tss *trx_volume_get(trx_volume *volume, TEE_UUID *uuid);
TEE_Result trx_volume_serialize(trx_volume *volume, void *data, size_t *data_size);
TEE_Result trx_volume_deserialize(trx_volume *volume, void *data, size_t data_size);
char *trx_volume_gen_ree_basename(trx_volume *volume);

TEE_Result trx_volume_save(trx_volume *volume);
TEE_Result trx_volume_load(trx_volume *volume);

bool trx_volume_is_loaded(trx_volume *volume);

TEE_Result trx_volume_share_serialize(trx_volume *volume, void *data, size_t *data_size);
TEE_Result trx_volume_share_deserialize(trx_volume *volume, void *data, size_t data_size);
TEE_Result trx_volume_share(trx_volume *volume, char *R, size_t R_size, trx_ibme *ibme);
TEE_Result trx_volume_import(trx_volume *volume, char *S, size_t S_size, trx_ibme *ibme);

static const char trx_volume_ree_dirname_fmt[] = "volume_%lu.trx";
static const char trx_volume_ree_basename[] = "table.trx";
static const char trx_volume_id[] = "table";

#endif //TRX_TRX_VOLUME_H