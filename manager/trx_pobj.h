#ifndef TRX_TRX_POBJ_H
#define TRX_TRX_POBJ_H

#include <tee_internal_api.h>
#include <utee_defines.h>
#include <sys/queue.h>
#include "trx_tss.h"
#include "trx_file.h"

struct _trx_tss;

typedef struct _trx_pobj
{
    char *id;
    size_t id_size;
    struct _trx_tss *tss;
    void *data;
    size_t data_size;
    struct _trx_file *file;
} trx_pobj;

trx_pobj *trx_pobj_init(void);
void trx_pobj_clear(trx_pobj *pobj);
int trx_pobj_save(trx_pobj *pobj);
int trx_pobj_load(trx_pobj *pobj);

int trx_pobj_snprint(char *s, size_t n, trx_pobj *pobj);
int trx_pobj_set_str(char *s, size_t n, trx_pobj *pobj);

typedef struct _pobj_entry
{
    trx_pobj *pobj;
    SLIST_ENTRY(_pobj_entry)
    _pobj_entries;
} pobj_entry;
typedef SLIST_HEAD(_pobj_list_head, _pobj_entry) pobj_list_head;

pobj_list_head *trx_pobj_list_init(void);
void trx_pobj_list_clear(pobj_list_head *h);
size_t trx_pobj_list_len(pobj_list_head *h);
trx_pobj *trx_pobj_list_get(const char *id, size_t id_size, pobj_list_head *h);
int trx_pobj_list_add(trx_pobj *pobj, pobj_list_head *h);
int trx_pobj_list_snprint(char *s, size_t n, pobj_list_head *h);
int trx_pobj_list_set_str(char *s, size_t n, pobj_list_head *h);

#endif //TRX_TRX_POBJ_H
