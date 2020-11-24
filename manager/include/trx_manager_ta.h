#ifndef TA_TRX_MANAGER_H
#define TA_TRX_MANAGER_H

#define TA_TRX_MANAGER_UUID                                \
    {                                                      \
        0xcc2fd8e5, 0x8acc, 0x4c3f,                        \
        {                                                  \
            0xa7, 0xa8, 0xd2, 0xb4, 0x1c, 0xf2, 0xae, 0xef \
        }                                                  \
    }

#define TA_TRX_MANAGER_CMD_SETUP 0
#define TA_TRX_MANAGER_CMD_WRITE 1
#define TA_TRX_MANAGER_CMD_READ 2
#define TA_TRX_MANAGER_CMD_LIST 3
#define TA_TRX_MANAGER_CMD_MOUNT 4
#define TA_TRX_MANAGER_CMD_SHARE 5

#endif