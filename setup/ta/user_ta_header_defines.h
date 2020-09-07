#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <trx_setup_ta.h>

#define TA_UUID         TA_TRX_SETUP_UUID

#define TA_FLAGS        TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE   (2 * 1024)
#define TA_DATA_SIZE    (32 * 1024)

#define TA_VERSION	"0.1"

#define TA_DESCRIPTION	"SETUP TA for TRX"

#endif