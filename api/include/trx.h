#ifndef TRX_H
#define TRX_H

#include <tee_internal_api.h>

TEE_Result trx_setup(const char *path, size_t path_size);
TEE_Result trx_write(const void *id, size_t id_size,
        const void *data, size_t data_size);
TEE_Result trx_read(const void *id, size_t id_size,
        void *data, size_t *data_size);
TEE_Result trx_list(void *id_list);

#endif //TRX_H