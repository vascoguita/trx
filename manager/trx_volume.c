#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <ree_fs_api.h>
#include <sys/queue.h>

#include "trx_manager_ta.h"
#include "trx_volume.h"
#include "trx_tss.h"
#include "trx_ibme.h"
#include "trx_utils.h"
#include "trx_keys.h"
#include "trx_cipher.h"

trx_volume *trx_volume_init(void)
{
    trx_volume *volume;

    DMSG("initializing volume");

    if ((volume = (struct _trx_volume *)malloc(sizeof(struct _trx_volume))) == NULL)
    {
        EMSG("failed calling function \'malloc\'");
        return NULL;
    }
    if (!(volume->vk = trx_vk_init()))
    {
        EMSG("failed calling function \'trx_vk_init\'");
        trx_volume_clear(volume);
        return NULL;
    }
    SLIST_INIT(&(volume->tss_table));
    volume->tss_table_len = 0;
    volume->next_pobj_ree_basename_n = 0;
    volume->mount_point = NULL;
    volume->mount_point_size = 0;
    volume->ree_dirname = NULL;
    volume->ree_dirname_size = 0;
    volume->version = 0;
    volume->isloaded = false;

    DMSG("initialized volume");
    return volume;
}

void trx_volume_clear(trx_volume *volume)
{
    tss_entry *e;

    DMSG("clearing volume");

    if (volume)
    {
        while (!SLIST_EMPTY(&(volume->tss_table)))
        {
            e = SLIST_FIRST(&(volume->tss_table));
            SLIST_REMOVE_HEAD(&(volume->tss_table), _tss_entries);
            trx_tss_clear(e->tss);
            free(e);
        }
        free(volume->mount_point);
        free(volume->ree_dirname);
        trx_vk_clear(volume->vk);
    }
    free(volume);

    DMSG("cleared volume");
}

trx_volume *trx_volume_create(char *mount_point, size_t mount_point_size, char *ree_dirname, size_t ree_dirname_size)
{
    TEE_Result res;
    trx_volume *volume;

    DMSG("creating volume, mount_point: \"%s\", mount_point_size: %zu, ree_dirname_size: \"%s\", ree_dirname_size: %zu",
         mount_point, mount_point_size, ree_dirname, ree_dirname_size);

    if (!(volume = trx_volume_init()))
    {
        EMSG("failed calling function \'trx_volume_init\'");
        return NULL;
    }
    res = trx_vk_gen(volume->vk);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_vk_gen\'");
        trx_volume_clear(volume);
        return NULL;
    }
    if (!(volume->mount_point = strndup(mount_point, mount_point_size)))
    {
        EMSG("failed calling function \'strndup\'");
        trx_volume_clear(volume);
        return NULL;
    }
    volume->mount_point_size = mount_point_size;
    if (!(volume->ree_dirname = strndup(ree_dirname, ree_dirname_size)))
    {
        EMSG("failed calling function \'strndup\'");
        trx_volume_clear(volume);
        return NULL;
    }
    volume->ree_dirname_size = ree_dirname_size;
    volume->isloaded = true;

    DMSG("created volume, mount_point: \"%s\", mount_point_size: %zu, ree_dirname_size: \"%s\", ree_dirname_size: %zu",
         volume->mount_point, volume->mount_point_size, volume->ree_dirname, volume->ree_dirname_size);
    return volume;
}

char *trx_volume_gen_ree_basename(trx_volume *volume)
{
    static char bname[1024];
    int bname_size = 1024;

    DMSG("generating ree_basename for pobj");

    if (!snprintf(bname, bname_size, trx_pobj_ree_basename_fmt, volume->next_pobj_ree_basename_n))
    {
        EMSG("failed calling function \'snprintf\'");
        return NULL;
    }
    volume->next_pobj_ree_basename_n++;

    DMSG("generated ree_basename for pobj: \"%s\"", bname);
    return bname;
}

TEE_Result trx_volume_add(trx_volume *volume, trx_tss *tss)
{
    tss_entry *e;

    DMSG("adding tss to volume");

    if (!(e = malloc(sizeof(struct _tss_entry))))
    {
        EMSG("failed calling function \'malloc\'");
        return TEE_ERROR_GENERIC;
    }
    e->tss = tss;
    SLIST_INSERT_HEAD(&(volume->tss_table), e, _tss_entries);
    volume->tss_table_len++;
    tss->volume = volume;

    DMSG("added tss to volume, number of tss entries: %lu", volume->tss_table_len);
    return TEE_SUCCESS;
}

struct _trx_tss *trx_volume_get(trx_volume *volume, TEE_UUID *uuid)
{
    tss_entry *e;

    DMSG("getting tss from volume");

    SLIST_FOREACH(e, &(volume->tss_table), _tss_entries)
    {
        if (memcmp(e->tss->uuid, uuid, sizeof(TEE_UUID)) == 0)
        {
            DMSG("got tss from volume");
            return e->tss;
        }
    }
    DMSG("did not get tss from volume");
    return NULL;
}

TEE_Result trx_volume_serialize(trx_volume *volume, void *data, size_t *data_size)
{
    size_t exp_dst_size;
    tss_entry *e;
    size_t tmp_size;
    uint8_t *cpy_ptr;
    TEE_Result res;

    DMSG("checking required buffer size to serialize volume");

    if (!volume)
    {
        EMSG("failed checking if volume is not NULL");
        return TEE_ERROR_GENERIC;
    }

    exp_dst_size = sizeof(unsigned long int);
    SLIST_FOREACH(e, &(volume->tss_table), _tss_entries)
    {
        res = trx_tss_serialize(e->tss, NULL, &tmp_size);
        if (res != TEE_ERROR_SHORT_BUFFER)
        {
            EMSG("failed calling function \'trx_tss_serialize\'");
            return TEE_ERROR_GENERIC;
        }
        exp_dst_size += sizeof(size_t);
        exp_dst_size += tmp_size;
    }
    exp_dst_size += sizeof(unsigned long int);

    if (!data)
    {
        *data_size = exp_dst_size;
        DMSG("defining required buffer size to serialize volume: %zu", *data_size);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*data_size != exp_dst_size)
    {
        EMSG("failed checking size of \"data\" buffer, provided_size: %zu, required_size: %zu", *data_size, exp_dst_size);
        return TEE_ERROR_GENERIC;
    }

    DMSG("serializing volume");

    cpy_ptr = data;
    memcpy(cpy_ptr, &(volume->tss_table_len), sizeof(unsigned long int));
    cpy_ptr += sizeof(unsigned long int);
    SLIST_FOREACH(e, &(volume->tss_table), _tss_entries)
    {
        res = trx_tss_serialize(e->tss, NULL, &tmp_size);
        if (res != TEE_ERROR_SHORT_BUFFER)
        {
            EMSG("failed calling function \'trx_tss_serialize\'");
            return TEE_ERROR_GENERIC;
        }
        memcpy(cpy_ptr, &tmp_size, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        res = trx_tss_serialize(e->tss, cpy_ptr, &tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_tss_serialize\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += tmp_size;
    }
    memcpy(cpy_ptr, &(volume->next_pobj_ree_basename_n), sizeof(unsigned long int));
    cpy_ptr += sizeof(unsigned long int);

    DMSG("serialized volume");

    return TEE_SUCCESS;
}

TEE_Result trx_volume_deserialize(trx_volume *volume, void *data, size_t data_size)
{
    uint8_t *cpy_ptr;
    size_t left, tmp_size;
    long unsigned int i;
    TEE_Result res;
    trx_tss *tss;

    DMSG("deserializing volume from buffer with size: %zu", data_size);

    if (!data || !volume || !data_size)
    {
        EMSG("failed calling checking if volume is not NULL or \"data\" buffer is not NULL"
             "or size of \"data\" buffer is greater than 0");
        return TEE_ERROR_GENERIC;
    }

    cpy_ptr = data;
    left = data_size;
    if (left < sizeof(unsigned long int))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(&i, cpy_ptr, sizeof(unsigned long int));
    cpy_ptr += sizeof(unsigned long int);
    left -= sizeof(unsigned long int);

    while (volume->tss_table_len < i)
    {
        if (!(tss = trx_tss_init()))
        {
            EMSG("failed calling function \'trx_tss_init\'");
            return TEE_ERROR_GENERIC;
        }
        res = trx_volume_add(volume, tss);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_volume_add\'");
            trx_tss_clear(tss);
            return TEE_ERROR_GENERIC;
        }
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            return TEE_ERROR_GENERIC;
        }
        memcpy(&tmp_size, cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        res = trx_tss_deserialize(tss, cpy_ptr, tmp_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("failed calling function \'trx_tss_deserialize\'");
            return TEE_ERROR_GENERIC;
        }
        cpy_ptr += tmp_size;
        left -= tmp_size;
    }
    if (left < sizeof(long unsigned int))
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }
    memcpy(&(volume->next_pobj_ree_basename_n), cpy_ptr, sizeof(unsigned long int));
    cpy_ptr += sizeof(unsigned long int);
    left -= sizeof(unsigned long int);

    if (left != 0)
    {
        EMSG("failed checking size of \"data\" buffer");
        return TEE_ERROR_GENERIC;
    }

    DMSG("deserialized volume");

    return TEE_SUCCESS;
}

TEE_Result trx_volume_save(trx_volume *volume)
{
    TEE_Result res;
    int fd;
    uint8_t *data_enc, sizeof_size, *data = NULL, *volume_data = NULL;
    size_t data_size, data_enc_size, ree_path_size, volume_data_size, id_size;
    char *ree_path;
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;

    volume->version++;

    DMSG("saving volume, version: %lu", volume->version);

    res = trx_volume_serialize(volume, volume_data, &volume_data_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        EMSG("failed calling function \'trx_volume_serialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(volume_data = malloc(volume_data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_volume_serialize(volume, volume_data, &volume_data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_serialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    id_size = strlen(trx_volume_id) + 1;

    res = trx_cipher_encrypt(volume->vk, &uuid, volume_data, volume_data_size,
                             volume->version, trx_volume_id, id_size, NULL, &data_enc_size);
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

    res = trx_cipher_encrypt(volume->vk, &uuid, volume_data, volume_data_size,
                             volume->version, trx_volume_id, id_size, data_enc, &data_enc_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_cipher_encrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(ree_path = path(volume->ree_dirname, trx_volume_ree_basename)))
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

    DMSG("saved volume, version: %lu", volume->version);
out:
    free(volume_data);
    free(data);
    ree_fs_api_close(fd);
    return res;
}

TEE_Result trx_volume_load(trx_volume *volume)
{
    int fd;
    TEE_Result res;
    uint8_t *data = NULL, sizeof_size, *volume_data = NULL;
    size_t data_size, ree_path_size, tmp_size, volume_data_size, id_size;
    char *ree_path;
    TEE_UUID uuid = TA_TRX_MANAGER_UUID;

    DMSG("loading volume");

    if (!(ree_path = path(volume->ree_dirname, trx_volume_ree_basename)))
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

    id_size = strlen(trx_volume_id) + 1;

    res = trx_cipher_decrypt(volume->vk, &uuid, data, data_size, &(volume->version), trx_volume_id, id_size, NULL, &volume_data_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        EMSG("failed calling function \'trx_cipher_decrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(volume_data = malloc(volume_data_size)))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_cipher_decrypt(volume->vk, &uuid, data, data_size, &(volume->version), trx_volume_id, id_size, volume_data, &volume_data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_cipher_decrypt\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_volume_deserialize(volume, volume_data, volume_data_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_volume_deserialize\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    volume->isloaded = true;

    DMSG("loaded volume, version: %lu", volume->version);

out:
    ree_fs_api_close(fd);
    free(data);
    free(volume_data);
    return res;
}

bool trx_volume_is_loaded(trx_volume *volume)
{
    DMSG("checking if volume is loaded");

    if (volume->isloaded)
    {
        DMSG("volume is loaded");
    }
    else
    {
        DMSG("volume is not loaded");
    }
    return volume->isloaded;
}

TEE_Result trx_volume_share(trx_volume *volume, char *R, size_t R_size)
{
    TEE_Result res;
    uint32_t buffer_size;
    trx_ibme *ibme = NULL;
    Cipher *vk_enc = NULL;
    uint8_t buffer[trx_vk_size];
    void *data = NULL;
    char *ree_path;
    size_t data_size, ree_path_size;
    int fd;

    buffer_size = trx_vk_size;

    DMSG("sharing volume");

    if (!volume || !R || !R_size)
    {
        EMSG("failed calling checking if volume is not NULL or receiver id is not NULL"
             "or size of receiver id is greater than 0");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_vk_to_bytes(volume->vk, buffer, &buffer_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_vk_to_bytes\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("failed calling function \'trx_ibme_init\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_load\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(vk_enc = Cipher_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'Cipher_init\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (1 == ibme_enc(*(ibme->pairing), ibme->mpk, ibme->ek, (unsigned char *)R, R_size, buffer,
                      buffer_size, vk_enc))
    {
        EMSG("failed calling function \'ibme_enc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if ((data_size = Cipher_snprint(NULL, 0, vk_enc) + 1) < 1)
    {
        EMSG("failed calling function \'Cipher_snprint\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(data = malloc(data_size + sizeof(size_t))))
    {
        EMSG("failed calling function \'malloc\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    memcpy(data, &data_size, sizeof(size_t));

    if (data_size != (size_t)(Cipher_snprint((char *)data + sizeof(size_t), data_size, vk_enc) + 1))
    {
        EMSG("failed calling function \'Cipher_snprint\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    ree_path = path(volume->ree_dirname, trx_vk_ree_basename);
    ree_path_size = strlen(ree_path) + 1;

    res = ree_fs_api_create(ree_path, ree_path_size, &fd);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'ree_fs_api_create\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = ree_fs_api_write(fd, 0, data, data_size + sizeof(size_t));
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'ree_fs_api_write\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("shared volume");

out:
    ree_fs_api_close(fd);
    free(data);
    Cipher_clear(vk_enc);
    trx_ibme_clear(ibme);
    return res;
}

TEE_Result trx_volume_import(trx_volume *volume, char *S, size_t S_size)
{
    uint32_t buffer_size;
    trx_ibme *ibme = NULL;
    Cipher *vk_enc = NULL;
    TEE_Result res;
    uint8_t buffer[trx_vk_size];
    void *data = NULL;
    char *ree_path = NULL;
    size_t ree_path_size, data_size, tmp_size;
    int fd;

    buffer_size = trx_vk_size;

    DMSG("importing volume");

    if (!(ree_path = path(volume->ree_dirname, trx_vk_ree_basename)))
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

    tmp_size = sizeof(size_t);
    res = ree_fs_api_read(fd, 0, &data_size, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != sizeof(size_t)))
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
    res = ree_fs_api_read(fd, sizeof(size_t), data, &tmp_size);
    if ((res != TEE_SUCCESS) || (tmp_size != data_size))
    {
        EMSG("failed calling function \'ree_fs_api_read\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    if (!(ibme = trx_ibme_init()))
    {
        EMSG("failed calling function \'trx_ibme_init\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_ibme_load(ibme);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_ibme_load\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(vk_enc = Cipher_init(*(ibme->pairing))))
    {
        EMSG("failed calling function \'Cipher_init\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (0 == Cipher_set_str(data, data_size, vk_enc))
    {
        EMSG("failed calling function \'Cipher_set_str\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    tmp_size = buffer_size;
    if (ibme_dec(*(ibme->pairing), ibme->dk, (unsigned char *)S, S_size, vk_enc, (unsigned char *)buffer, &tmp_size) != 0)
    {
        EMSG("failed calling function \'ibme_dec\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    res = trx_vk_from_bytes(volume->vk, buffer, buffer_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("failed calling function \'trx_vk_from_bytes\'");
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    DMSG("imported volume");

out:
    Cipher_clear(vk_enc);
    trx_ibme_clear(ibme);
    free(data);
    ree_fs_api_close(fd);
    return res;
}