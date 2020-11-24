#ifndef TRX_TSS_H
#define TRX_TSS_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_db.h"
#include "trx_pobj.h"

struct _pobj_list_head;
struct _trx_db;

typedef struct _trx_tss
{
    TEE_UUID *uuid;
    struct _pobj_list_head *pobj_lh;
    struct _trx_db *db;
} trx_tss;

trx_tss *trx_tss_init(void);
void trx_tss_clear(trx_tss *tss);
int trx_tss_snprint(char *s, size_t n, trx_tss *tss);
int trx_tss_set_str(char *s, size_t n, trx_tss *tss);

typedef struct _tss_entry
{
    trx_tss *tss;
    SLIST_ENTRY(_tss_entry)
    _tss_entries;
} tss_entry;
typedef SLIST_HEAD(_tss_list_head, _tss_entry) tss_list_head;

tss_list_head *trx_tss_list_init(void);
void trx_tss_list_clear(tss_list_head *h);
size_t trx_tss_list_len(tss_list_head *h);
trx_tss *trx_tss_list_get(const TEE_UUID *uuid, tss_list_head *h);
int trx_tss_list_add(trx_tss *tss, tss_list_head *h);
int trx_tss_list_snprint(char *s, size_t n, tss_list_head *h);
int trx_tss_list_set_str(char *s, size_t n, tss_list_head *h);

#endif //TRX_TSS_H
