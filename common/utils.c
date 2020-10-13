#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <tee_internal_api.h>
#include <stdio.h>

#include "utils.h"

void clip_sub(size_t *result, int status, size_t *left, size_t n) {
    *result += status;
    *left = *result >= n ? 0 : n - *result;
}

char *basename(const char *path)
{
    static char bname[PATH_MAX];
    size_t len;
    const char *endp, *startp;

    /* Empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        bname[0] = '.';
        bname[1] = '\0';
        return (bname);
    }

    /* Strip any trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* All slashes becomes "/" */
    if (endp == path && *endp == '/') {
        bname[0] = '/';
        bname[1] = '\0';
        return (bname);
    }

    /* Find the start of the base */
    startp = endp;
    while (startp > path && *(startp - 1) != '/')
        startp--;

    len = endp - startp + 1;
    if (len >= sizeof(bname)) {
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
    if (path == NULL || *path == '\0') {
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
    if (endp == path) {
        dname[0] = *endp == '/' ? '/' : '.';
        dname[1] = '\0';
        return (dname);
    } else {
        /* Move forward past the separating slashes */
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

int tee_uuid_snprint(char *s, size_t n, TEE_UUID *uuid)
{
    size_t result, left;
    int status, i;

    result = 0;

    status = snprintf(s, n, "%x", uuid->timeLow);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", uuid->timeMid);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "-%x", uuid->timeHiAndVersion);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < 8; i++) {
        if((i == 0) || (i == 2)) {
            status = snprintf(s + result, left, "-%x", uuid->clockSeqAndNode[i]);
        } else {
            status = snprintf(s + result, left, "%x", uuid->clockSeqAndNode[i]);
        }
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    return (int)result;
}

int pad(const uint8_t *data, size_t data_size, uint8_t bs, uint8_t *p, size_t *p_size)
{
    uint8_t padding_byte;
    size_t tmp_p_size, i;

    tmp_p_size = (data_size / bs + 1) * bs;
    padding_byte = (uint8_t)(tmp_p_size - data_size);

    if((p == NULL) && (*p_size == 0)) {
        *p_size = tmp_p_size;
        return 0;
    }

    if(p == NULL || (*p_size != tmp_p_size)) {
        return 1;
    }

    memcpy(p, data, data_size);

    for(i = data_size; i < *p_size; i++) {
        p[i] = padding_byte;
    }

    return 0;
}

int unpad(const uint8_t *p, size_t p_size, uint8_t bs, uint8_t *data, size_t *data_size) {
    uint8_t padding_byte;
    size_t tmp_data_size, i;

    if (p == NULL || (p_size % bs)) {
        return 1;
    }

    if (!(padding_byte = p[p_size - 1])) {
        return 1;
    }

    tmp_data_size = p_size - padding_byte;

    for (i = tmp_data_size; i < p_size; i++) {
        if (p[i] != padding_byte) {
            return 1;
        }
    }

    if ((data == NULL) && (*data_size == 0)) {
        *data_size = tmp_data_size;
        return 0;
    }
    if ((data == NULL) || (*data_size != tmp_data_size)) {
        return 1;
    }

    memcpy(data, p, *data_size);
    return 0;
}