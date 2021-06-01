#include "trx_authorization.h"
#include "trx_authentication.h"

#include <tee_internal_api.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <tui/tui.h>

bool trx_authorization_authorize(trx_authentication *auth, const char *fmt, ...)
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

    return trx_authentication_check(auth, input);
}

bool trx_authorization_share(trx_authentication *auth, const char *mount_point, const char *R, const unsigned long int version, const char *label)
{
    return trx_authorization_authorize(auth,
                                       "Authorize Secure Storage Volume mounted on \"%s\""
                                       " with version %lu and label \"%s\""
                                       " to be shared with \"%s\"?\nPIN: ",
                                       mount_point, version, label, R);
}

bool trx_authorization_mount(trx_authentication *auth, const char *mount_point, const char *S, const unsigned long int version, const char *label)
{
    return trx_authorization_authorize(auth,
                                       "Authorize Secure Storage Volume from \"%s\""
                                       " with version %lu and label \"%s\""
                                       " to be mounted on \"%s\"?\nPIN: ",
                                       S, version, label, mount_point);
}