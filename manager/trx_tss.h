#ifndef TRX_TSS_H
#define TRX_TSS_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_volume.h"
#include "trx_pobj.h"

struct _trx_volume;
struct _trx_pobj;

typedef struct _pobj_entry
{
    struct _trx_pobj *pobj;
    SLIST_ENTRY(_pobj_entry)
    _pobj_entries;
} pobj_entry;
typedef SLIST_HEAD(_pobj_table_head, _pobj_entry) pobj_table_head;

typedef struct _trx_tss
{
    pobj_table_head pobj_table;
    long unsigned int pobj_table_len;
    TEE_UUID *uuid;
    struct _trx_volume *volume;
} trx_tss;

trx_tss *trx_tss_init(void);
void trx_tss_clear(trx_tss *tss);
trx_tss *trx_tss_create(TEE_UUID *uuid);
TEE_Result trx_tss_add(trx_tss *tss, struct _trx_pobj *pobj);
struct _trx_pobj *trx_tss_get(trx_tss *tss, const char *id, size_t id_size);

TEE_Result trx_tss_serialize(trx_tss *tss, void *data, size_t *data_size);
TEE_Result trx_tss_deserialize(trx_tss *tss, void *data, size_t data_size);

#endif //TRX_TSS_H
