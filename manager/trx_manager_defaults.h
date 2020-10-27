#ifndef TRX_TRX_MANAGER_DEFAULTS_H
#define TRX_TRX_MANAGER_DEFAULTS_H

#include <stdio.h>
#include <tee_api_defines.h>

#define DEFAULT_DB_ID               "db"
#define DEFAULT_DB_LIST_ID          "db_list"
#define DEFAULT_IBME_ID             "ibme"
#define DEFAULT_REE_DIRNAME         "trx"
#define DEFAULT_REE_DIRNAME_SIZE    4
#define AES_KEY_BIT_SIZE            256 // 128, 192, or 256 bits
#define AES_KEY_SIZE                AES_KEY_BIT_SIZE / 8
#define IV_SIZE                     16
#define HMACSHA256_KEY_BIT_SIZE     256
#define HMACSHA256_KEY_SIZE         HMACSHA256_KEY_BIT_SIZE / 8
#define HMACSHA256_BLOCK_SIZE       64
#define HMACSHA256_TAG_SIZE         32

#endif //TRX_TRX_MANAGER_DEFAULTS_H
