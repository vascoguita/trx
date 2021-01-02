#include "trx_authorization.h"

#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <tui/tui.h>

bool trx_authorization_authorize(const char *fmt, ...)
{
    size_t m_size, input_size;
    char *m;
    char input[100];
    va_list arg;
    TEE_Result res;

    input_size = 100;

    va_start(arg, fmt);

    if ((m_size = vsnprintf(NULL, 0, fmt, arg) + 1) < 1)
    {
        va_end(arg);
        return false;
    }
    if (!(m = malloc(m_size)))
    {
        va_end(arg);
        return false;
    }
    if (m_size != (size_t)(vsnprintf(m, m_size, fmt, arg) + 1))
    {
        free(m);
        va_end(arg);
        return false;
    }
    va_end(arg);

    res = TUI->input(m, input, input_size);
    if (res != TEE_SUCCESS)
    {
        free(m);
        return false;
    }
    free(m);
    if (strncmp(input, "y", strlen("y")) != 0)
    {
        return false;
    }
    return true;
}

bool trx_authorization_share(const char *mount_point, const char *R)
{
    return trx_authorization_authorize("Authorize Secure Storage Volume mounted on \"%s\""
                                        " to be shared with \"%s\"? [y\\n] ", mount_point, R);
}

bool trx_authorization_mount(const char *mount_point, const char *S)
{
    return trx_authorization_authorize("Authorize Secure Storage Volume from \"%s\""
                                        " to be mounted on \"%s\"? [y\\n] ", S, mount_point);
}