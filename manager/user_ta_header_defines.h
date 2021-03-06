#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <trx_manager_ta.h>

#define TA_UUID TA_TRX_MANAGER_UUID

#define TA_FLAGS TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE (64 * 1024)
#define TA_DATA_SIZE (3 * 1024 * 1024)

#define TA_VERSION "0.1"

#define TA_DESCRIPTION "TRX Manager TA"

#endif