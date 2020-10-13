#ifndef TRX_TRX_MANAGER_DEFAULTS_H
#define TRX_TRX_MANAGER_DEFAULTS_H

#include <stdio.h>

#define DEFAULT_DB_ID       "db"
#define DEFAULT_DB_LIST_ID  "db_list"
#define BK_BIT_SIZE         128 // 128, 192, or 256 bits
#define BK_TYPE             TEE_TYPE_AES
#define IV_SIZE             BK_BIT_SIZE / 8

#endif //TRX_TRX_MANAGER_DEFAULTS_H
