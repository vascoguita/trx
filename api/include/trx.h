#ifndef TRX_H
#define TRX_H

#include <tee_internal_api.h>

typedef TEE_TASessionHandle trx_handle;

TEE_Result trx_handle_init(trx_handle *handle);
void trx_handle_clear(trx_handle handle);
TEE_Result trx_write(trx_handle handle, const char *path, size_t path_size, const void *data, size_t data_size);
TEE_Result trx_read(trx_handle handle, const char *path, size_t path_size, void *data, size_t *data_size);
TEE_Result trx_mount(trx_handle handle, const unsigned char *S, size_t S_size,
                     const char *ree_dirname, size_t ree_dirname_size, const char *mount_point, size_t mount_point_size);
TEE_Result trx_share(trx_handle handle, const unsigned char *R, size_t R_size, const char *mount_point,
                     size_t mount_point_size, const char *label, size_t label_size);

#endif //TRX_H