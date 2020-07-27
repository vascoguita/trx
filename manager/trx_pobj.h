#ifndef TRX_TRX_POBJ_H
#define TRX_TRX_POBJ_H

#include <tee_internal_api.h>
#include <sys/queue.h>

typedef struct _trx_pobj {
    void *id;
    size_t id_size;
    unsigned long ree_id;
} trx_pobj;

int trx_pobj_init(trx_pobj **pobj);
void trx_pobj_clear(trx_pobj *pobj);
int trx_pobj_snprint(char *s, size_t n, trx_pobj *pobj);
int trx_pobj_set_str(char *s, size_t n, trx_pobj *pobj);

typedef struct _pobj_entry {
    trx_pobj *pobj;
    SLIST_ENTRY(_pobj_entry) _pobj_entries;
} pobj_entry;
typedef SLIST_HEAD(_pobj_list_head, _pobj_entry) pobj_list_head;

int trx_pobj_list_init(pobj_list_head **h);
void trx_pobj_list_clear(pobj_list_head *h);
size_t trx_pobj_list_len(pobj_list_head *h);
trx_pobj *trx_pobj_list_get(void *id, size_t id_size, pobj_list_head *h);
int trx_pobj_list_add(trx_pobj *pobj, pobj_list_head *h);
int trx_pobj_list_snprint(char *s, size_t n, pobj_list_head *h);
int trx_pobj_list_set_str(char *s, size_t n, pobj_list_head *h);

#endif //TRX_TRX_POBJ_H
