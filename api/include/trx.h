#ifndef TRX_H
#define TRX_H

#include <tee_internal_api.h>

TEE_Result trx_setup(const char *param_str, size_t param_str_size,
                     const char *mpk_str, size_t mpk_str_size,
                     const char *ek_str, size_t ek_str_size,
                     const char *dk_str, size_t dk_str_size);
TEE_Result trx_write(const char *path, size_t path_size, const void *data, size_t data_size);
TEE_Result trx_read(const char *path, size_t path_size, void *data, size_t *data_size);
TEE_Result trx_list(void *data, size_t *data_size);
TEE_Result trx_mount(const unsigned char *S, size_t S_size, const char *ree_dirname, size_t ree_dirname_size, const char *mount_point, size_t mount_point_size);
TEE_Result trx_share(const unsigned char *R, size_t R_size, const char *mount_point, size_t mount_point_size);

#endif //TRX_H