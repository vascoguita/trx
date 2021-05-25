#ifndef TRX_SETUP_H
#define TRX_SETUP_H

#include <stdio.h>
#include <tee_client_api.h>

void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
int trx_setup(TEEC_Session *sess,
              char *param_str, size_t param_str_size,
              char *mpk_str, size_t mpk_str_size,
              char *ek_str, size_t ek_str_size,
              char *dk_str, size_t dk_str_size,
              char *udid, size_t udid_size);
int serialize(char *param_str, size_t param_str_size,
              char *mpk_str, size_t mpk_str_size,
              char *ek_str, size_t ek_str_size,
              char *dk_str, size_t dk_str_size,
              char *udid, size_t udid_size,
              void *data, size_t *data_size);

#endif