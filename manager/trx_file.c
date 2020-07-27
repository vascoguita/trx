#include "trx_file.h"
#include <stdio.h>

trx_file *trx_file_init()
{
    trx_file *f;

    if((f = (struct _trx_file *)malloc(sizeof(struct _trx_file))) == NULL) {
        return NULL;
    }
    if((f->metadata = (struct _trx_metadata *)malloc(sizeof(struct _trx_metadata))) == NULL) {
        free(f);
        return NULL;
    }

    return f;
}


void trx_file_clear(trx_file *f)
{
    if(f){
        free(f->metadata);
        free(f);
    }
}

int trx_file_save(trx_file *f, char *filename, size_t filename_size)
{
    int fd;
    TEE_Result res;

    res = ree_fs_api_create(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        return 1;
    }
    res = ree_fs_api_write(fd, 0, f->metadata, sizeof(struct _trx_metadata));
    if(res != TEE_SUCCESS) {
        ree_fs_api_close(fd);
        return 1;
    }
    res = ree_fs_api_write(fd, sizeof(struct _trx_metadata), f->content, f->metadata->size);
    if(res != TEE_SUCCESS) {
        ree_fs_api_close(fd);
        return 1;
    }
    ree_fs_api_close(fd);
    return 0;
}

int trx_file_load(trx_file *f, char *filename, size_t filename_size){
    int fd;
    TEE_Result res;
    size_t metadata_size, content_size;

    res = ree_fs_api_open(filename, filename_size, &fd);
    if(res != TEE_SUCCESS) {
        return 1;
    }

    metadata_size = sizeof(struct _trx_metadata);
    res = ree_fs_api_read(fd, 0, f->metadata, &metadata_size);
    if((res != TEE_SUCCESS) || (metadata_size != sizeof(struct _trx_metadata))) {
        ree_fs_api_close(fd);
        return 1;
    }

    if((f->content = malloc(f->metadata->size)) == NULL){
        ree_fs_api_close(fd);
        return 1;
    }

    content_size = f->metadata->size;
    res = ree_fs_api_read(fd, metadata_size, f->content, &content_size);
    if((res != TEE_SUCCESS) || (content_size != f->metadata->size)) {
        free(f->content);
        ree_fs_api_close(fd);
        return 1;
    }
    ree_fs_api_close(fd);
    return 0;
}