#ifndef TRX_VOLUME_TABLE_H
#define TRX_VOLUME_TABLE_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "string.h"
#include "trx_volume.h"

typedef struct _volume_entry
{
    trx_volume *volume;
    SLIST_ENTRY(_volume_entry)
    _volume_entries;
} volume_entry;
typedef SLIST_HEAD(_volume_table_head, _volume_entry) volume_table_head;

typedef struct _trx_volume_table
{
    volume_table_head h;
    uint8_t len;
    long unsigned int next_volume_ree_dirname_n;
} trx_volume_table;

trx_volume_table *trx_volume_table_init(void);
void trx_volume_table_clear(trx_volume_table *volume_table);

TEE_Result trx_volume_table_add(trx_volume_table *volume_table, trx_volume *volume);
trx_volume *trx_volume_table_get(trx_volume_table *volume_table, char *mount_point, size_t mount_point_size);

TEE_Result trx_volume_table_save(trx_volume_table *volume_table);
TEE_Result trx_volume_table_load(trx_volume_table *volume_table);
bool trx_volume_table_exists(void);

TEE_Result trx_volume_table_serialize(trx_volume_table *volume_table, void *data, size_t *data_size);
TEE_Result trx_volume_table_deserialize(trx_volume_table *volume_table, void *data, size_t data_size);

TEE_Result trx_volume_table_serialize_paths(trx_volume_table *volume_table, TEE_UUID *uuid, void *data, size_t *data_size);

char *trx_volume_table_gen_ree_dirname(trx_volume_table *volume_table);

static const char trx_volume_table_id[] = "trx_volume_table";

#endif //TRX_VOLUME_TABLE_H