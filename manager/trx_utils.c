#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <tee_internal_api.h>
#include <stdio.h>

#include "trx_utils.h"

void clip_sub(size_t *result, int status, size_t *left, size_t n)
{
    *result += status;
    *left = *result >= n ? 0 : n - *result;
}

char *basename(const char *path)
{
    static char bname[PATH_MAX];
    size_t len;
    const char *endp, *startp;

    /* Empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0')
    {
        bname[0] = '.';
        bname[1] = '\0';
        return (bname);
    }

    /* Strip any trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* All slashes becomes "/" */
    if (endp == path && *endp == '/')
    {
        bname[0] = '/';
        bname[1] = '\0';
        return (bname);
    }

    /* Find the start of the base */
    startp = endp;
    while (startp > path && *(startp - 1) != '/')
        startp--;

    len = endp - startp + 1;
    if (len >= sizeof(bname))
    {
        return (NULL);
    }
    memcpy(bname, startp, len);
    bname[len] = '\0';
    return (bname);
}

char *dirname(const char *path)
{
    static char dname[PATH_MAX];
    size_t len;
    const char *endp;

    /* Empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0')
    {
        dname[0] = '.';
        dname[1] = '\0';
        return (dname);
    }

    /* Strip any trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* Find the start of the dir */
    while (endp > path && *endp != '/')
        endp--;

    /* Either the dir is "/" or there are no slashes */
    if (endp == path)
    {
        dname[0] = *endp == '/' ? '/' : '.';
        dname[1] = '\0';
        return (dname);
    }
    else
    {
        /* Move forward past the separating slashes */
        do
        {
            endp--;
        } while (endp > path && *endp == '/');
    }

    len = endp - path + 1;
    if (len >= sizeof(dname))
    {
        return (NULL);
    }
    memcpy(dname, path, len);
    dname[len] = '\0';
    return (dname);
}

char *path(const char *dirname, const char *basename)
{
    static char pname[PATH_MAX];

    if (!snprintf(pname, PATH_MAX, "%s/%s", dirname, basename))
    {
        return NULL;
    }

    return pname;    
}

int tee_uuid_snprint(char *s, size_t n, TEE_UUID *uuid)
{
    size_t result, left;
    int status, i;

    result = 0;

    status = snprintf(s, n, "%x", uuid->timeLow);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", uuid->timeMid);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", uuid->timeHiAndVersion);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; i < 8; i++)
    {
        if ((i == 0) || (i == 2))
        {
            status = snprintf(s + result, left, "-%x", uuid->clockSeqAndNode[i]);
        }
        else
        {
            status = snprintf(s + result, left, "%x", uuid->clockSeqAndNode[i]);
        }
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    return (int)result;
}
