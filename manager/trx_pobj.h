#ifndef TRX_TRX_POBJ_H
#define TRX_TRX_POBJ_H

#include <tee_internal_api.h>
#include <sys/queue.h>
#include "trx_tss.h"

struct _trx_tss;

typedef struct _trx_pobj
{
    char *id;
    size_t id_size;
    char *ree_basename;
    size_t ree_basename_size;
    struct _trx_tss *tss;
    void *data;
    size_t data_size;
    unsigned long int version;
    void *udid;
    size_t udid_size;
    size_t file_size;
} trx_pobj;

trx_pobj *trx_pobj_init(void);
void trx_pobj_clear(trx_pobj *pobj);
void trx_pobj_clear_data(trx_pobj *pobj);

trx_pobj *trx_pobj_create(char *ree_basename, size_t ree_basename_size,
                          char *id, size_t id_size, void *udid, size_t udid_size,
                          void *data, size_t data_size);
TEE_Result trx_pobj_set_data(trx_pobj *pobj, void *data, size_t data_size);
TEE_Result trx_pobj_set_id(trx_pobj *pobj, char *id, size_t id_size);
TEE_Result trx_pobj_set_udid(trx_pobj *pobj, void *udid, size_t udid_size);
TEE_Result trx_pobj_set_ree_basename(trx_pobj *pobj, char *ree_basename, size_t ree_basename_size);
TEE_Result trx_pobj_set_tss(trx_pobj *pobj, struct _trx_tss *tss);
TEE_Result trx_pobj_set_version(trx_pobj *pobj, unsigned long int version);
TEE_Result trx_pobj_set_data_size(trx_pobj *pobj, size_t data_size);
TEE_Result trx_pobj_set_file_size(trx_pobj *pobj, size_t file_size);

TEE_Result trx_pobj_save(trx_pobj *pobj);
TEE_Result trx_pobj_load(trx_pobj *pobj);

static const char trx_pobj_ree_basename_fmt[] = "%lu";

#endif //TRX_TRX_POBJ_H
