#ifndef TRX_DEMO_PRIVATE_H
#define TRX_DEMO_PRIVATE_H

#include <tee_internal_api.h>
#include <trx/trx.h>

TEE_Result write(trx_handle handle);
TEE_Result read(trx_handle handle);
//TEE_Result list(trx_handle handle);
TEE_Result mount(trx_handle handle);
TEE_Result share(trx_handle handle);

#endif