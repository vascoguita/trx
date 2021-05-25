#include "trx_pobj.h"
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include "trx_manager_private.h"
#include <ree_fs_api.h>
#include "trx_volume.h"
#include "trx_cipher.h"
#include "trx_utils.h"

trx_pobj *trx_pobj_init(void)
{
    trx_pobj *pobj;

    DMSG("initializing pobj");

    if ((pobj = (struct _trx_pobj *)malloc(sizeof(struct _trx_pobj))) == NULL)
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    pobj->ree_basename = NULL;
    pobj->ree_basename_size = 0;
    pobj->id = NULL;
    pobj->id_size = 0;
    pobj->tss = NULL;
    pobj->data = NULL;
    pobj->data_size = 0;
    pobj->version = 0;
    pobj->udid = NULL;
    pobj->udid_size = 0;

    DMSG("initialized pobj");

    return pobj;
}

void trx_pobj_clear(trx_pobj *pobj)
{
    DMSG("clearing pobj");

    if (pobj != NULL)
    {
        free(pobj->id);
        free(pobj->ree_basename);
        free(pobj->udid);
        trx_pobj_clear_data(pobj);
    }
    free(pobj);

    DMSG("cleared pobj");
}

void trx_pobj_clear_data(trx_pobj *pobj)
{
    DMSG("clearing pobj data");

    if (pobj->data != NULL)
    {
        free(pobj->data);
        pobj->data = NULL;
    }

    DMSG("cleared pobj data");
}

trx_pobj *trx_pobj_create(char *ree_basename, size_t ree_basename_size,
                          char *id, size_t id_size,
                          void *udid, size_t udid_size,
                          void *data, size_t data_size)
{
    trx_pobj *pobj;
    TEE_Result res;

    DMSG("creating pobj, ree_basename: \"%s\", ree_basename_size: %zu, id: \"%s\", id_size: %zu, udid: \"%s\", "
         "udid_size: %zu, data: \"%s\", data_size: %zu",
         ree_basename, ree_basename_size, id, id_size, (char *)udid, udid_size, (char *)data, data_size);

    if (!(pobj = trx_pobj_init()))
    {
        EMSG("failed calling function \'trx_pobj_init\'");
        return NULL;
    }
    res = trx_pobj_set_ree_basename(pobj, ree_basename, ree_basename_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_ree_basename\'");
        trx_pobj_clear(pobj);
        return NULL;
    }
    res = trx_pobj_set_id(pobj, id, id_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_id\'");
        trx_pobj_clear(pobj);
        return NULL;
    }
    res = trx_pobj_set_udid(pobj, udid, udid_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_udid\'");
        trx_pobj_clear(pobj);
        return NULL;
    }
    res = trx_pobj_set_data(pobj, data, data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_pobj_set_data\'");
        trx_pobj_clear(pobj);
        return NULL;
    }

    DMSG("created pobj, ree_basename: \"%s\", ree_basename_size: %zu, id: \"%s\", id_size: %zu, udid: \"%s\","
         "udid_size: %zu, data: \"%s\", data_size: %zu",
         pobj->ree_basename, pobj->ree_basename_size, pobj->id, pobj->id_size, (char *)(pobj->udid),
         pobj->udid_size, (char *)(pobj->data), pobj->data_size);
    return pobj;
}

TEE_Result trx_pobj_set_data(trx_pobj *pobj, void *data, size_t data_size)
{
    DMSG("setting pobj data: \"%s\", data_size: %zu", (char *)data, data_size);

    trx_pobj_clear_data(pobj);
    if (!(pobj->data = malloc(data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        return TEE_ERROR_GENERIC;
    }
    pobj->data_size = data_size;
    memcpy(pobj->data, data, data_size);

    DMSG("set pobj data: \"%s\", data_size: %zu", (char *)(pobj->data), pobj->data_size);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_data_size(trx_pobj *pobj, size_t data_size)
{
    DMSG("setting pobj data_size: %zu", data_size);

    pobj->data_size = data_size;

    DMSG("set pobj data_size: %zu", pobj->data_size);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_udid(trx_pobj *pobj, void *udid, size_t udid_size)
{
    DMSG("setting pobj udid: \"%s\", udid_size: %zu", (char *)udid, udid_size);

    free(pobj->udid);
    if (!(pobj->udid = malloc(udid_size)))
    {
        EMSG("failed calling function \'malloc\'");
        return TEE_ERROR_GENERIC;
    }
    pobj->udid_size = udid_size;
    memcpy(pobj->udid, udid, udid_size);

    DMSG("set pobj udid: \"%s\", udid_size: %zu", (char *)(pobj->udid), pobj->udid_size);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_id(trx_pobj *pobj, char *id, size_t id_size)
{
    DMSG("setting pobj id: \"%s\", id_size: %zu", id, id_size);

    free(pobj->id);
    if (!(pobj->id = strndup(id, id_size)))
    {
        EMSG("failed calling function \'strndup\'");
        return TEE_ERROR_GENERIC;
    }
    pobj->id_size = id_size;

    DMSG("set pobj id: \"%s\", id_size: %zu", pobj->id, pobj->id_size);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_ree_basename(trx_pobj *pobj, char *ree_basename, size_t ree_basename_size)
{
    DMSG("setting pobj ree_basename: \"%s\", ree_basename_size: %zu", ree_basename, ree_basename_size);

    free(pobj->ree_basename);
    if (!(pobj->ree_basename = strndup(ree_basename, ree_basename_size)))
    {
        EMSG("failed calling function \'strndup\'");
        return TEE_ERROR_GENERIC;
    }
    pobj->ree_basename_size = ree_basename_size;

    DMSG("set pobj ree_basename: \"%s\", ree_basename_size: %zu", pobj->ree_basename, pobj->ree_basename_size);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_tss(trx_pobj *pobj, struct _trx_tss *tss)
{
    DMSG("setting pobj tss");

    if (!tss)
    {
        EMSG("failed checking if tss is not NULL");
        return TEE_ERROR_GENERIC;
    }

    pobj->tss = tss;

    DMSG("set pobj tss");
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_set_version(trx_pobj *pobj, unsigned long int version)
{
    DMSG("setting pobj version: %lu", version);

    pobj->version = version;

    DMSG("set pobj version: %lu", pobj->version);
    return TEE_SUCCESS;
}

TEE_Result trx_pobj_save(trx_pobj *pobj)
{
    TEE_Result res;
    int fd;
    uint8_t *data_enc, sizeof_size, *data = NULL;
    size_t data_size, data_enc_size, ree_path_size;
    char *ree_path;

    pobj->version++;

    if (pobj->udid_size != ibme->udid_size)
    {
        res = trx_pobj_set_udid(pobj, ibme->udid, ibme->udid_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_udid\'");
            res = TEE_ERROR_GENERIC;
            goto out;
        }
    }
    else if (memcmp(pobj->udid, ibme->udid, ibme->udid_size))
    {
        res = trx_pobj_set_udid(pobj, ibme->udid, ibme->udid_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_pobj_set_udid\'");
            res = TEE_ERROR_GENERIC;
            goto out;
        }
    }

    DMSG("saving pobj, version: %lu, udid: %s, udid_size: %zu", pobj->version, (char *)pobj->udid, pobj->udid_size);

    res = trx_cipher_encrypt(pobj->tss->volume->vk, pobj->tss->uuid, pobj->data,
                             pobj->data_size, pobj->version, pobj->id, pobj->id_size,
                             pobj->udid, pobj->udid_size, NULL, &data_enc_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        EMSG("failed calling function \'trx_cipher_encrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    sizeof_size = sizeof(size_t);
    data_size = sizeof_size + data_enc_size;
    if (!(data = malloc(data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    memcpy(data, &data_enc_size, sizeof_size);
    data_enc = data + sizeof_size;

    res = trx_cipher_encrypt(pobj->tss->volume->vk, pobj->tss->uuid, pobj->data,
                             pobj->data_size, pobj->version, pobj->id, pobj->id_size,
                             pobj->udid, pobj->udid_size, data_enc, &data_enc_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_cipher_encrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(ree_path = path(pobj->tss->volume->ree_dirname, pobj->ree_basename)))
    {
        EMSG("failed calling function \'path\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    ree_path_size = strlen(ree_path) + 1;

    res = ree_fs_api_create(ree_path, ree_path_size, &fd);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'ree_fs_api_create\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = ree_fs_api_write(fd, 0, data, data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'ree_fs_api_write\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("saved pobj, version: %lu", pobj->version);

out:
    free(data);
    ree_fs_api_close(fd);
    return res;
}

TEE_Result trx_pobj_load(trx_pobj *pobj)
{
    int fd;
    TEE_Result res;
    uint8_t *data = NULL, sizeof_size;
    size_t data_size, ree_path_size, tmp_size;
    char *ree_path;

    DMSG("loading pobj");

    if (!(ree_path = path(pobj->tss->volume->ree_dirname, pobj->ree_basename)))
    {
        EMSG("failed calling function \'path\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    ree_path_size = strlen(ree_path) + 1;

    res = ree_fs_api_open(ree_path, ree_path_size, &fd);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'ree_fs_api_open\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    sizeof_size = sizeof(size_t);
    tmp_size = sizeof_size;
    res = ree_fs_api_read(fd, 0, &data_size, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != sizeof_size))
    {
        EMSG("failed calling function \'ree_fs_api_read\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(data = malloc(data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    tmp_size = data_size;
    res = ree_fs_api_read(fd, sizeof_size, data, &tmp_size);

    if ((res != TEE_SUCCESS) || (tmp_size != data_size))
    {
        EMSG("failed calling function \'ree_fs_api_read\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    trx_pobj_clear_data(pobj);

    if (!(pobj->data = malloc(pobj->data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_cipher_decrypt(pobj->tss->volume->vk, pobj->tss->uuid, data, data_size,
                             pobj->version, pobj->id, pobj->id_size,
                             pobj->udid, pobj->udid_size, pobj->data, &(pobj->data_size));
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_cipher_decrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("loaded pobj, version: %lu", pobj->version);

out:
    ree_fs_api_close(fd);
    free(data);
    return res;
}