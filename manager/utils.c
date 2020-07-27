#include <stddef.h>
#include <limits.h>
#include <string.h>

#include "utils.h"

void clip_sub(size_t *result, int status, size_t *left, size_t n) {
    *result += status;
    *left = *result >= n ? 0 : n - *result;
}

char *dirname(const char *path)
{
    static char dname[256];
    size_t len;
    const char *endp;

    if (path == NULL || *path == '\0') {
        dname[0] = '.';
        dname[1] = '\0';
        return (dname);
    }

    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    while (endp > path && *endp != '/')
        endp--;

    /* Either the dir is "/" or there are no slashes */
    if (endp == path) {
        dname[0] = *endp == '/' ? '/' : '.';
        dname[1] = '\0';
        return (dname);
    } else {
        do {
            endp--;
        } while (endp > path && *endp == '/');
    }

    len = endp - path + 1;
    if (len >= sizeof(dname)) {
        return (NULL);
    }
    memcpy(dname, path, len);
    dname[len] = '\0';
    return (dname);
}