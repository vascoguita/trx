#ifndef TRX_H
#define TRX_H

#include <tee_internal_api.h>
#include <trx_path.h>

TEE_Result trx_setup(const char *ree_dirname, size_t ree_dirname_size);
TEE_Result trx_write(const char *path, size_t path_size, const void *data, size_t data_size);
TEE_Result trx_read(const char *path, size_t path_size, void *data, size_t *data_size);
TEE_Result trx_list(path_list_head *h);
TEE_Result trx_mount(const char *ree_dirname, size_t ree_dirname_size, const char *mount_point, size_t mount_point_size);

#endif //TRX_H