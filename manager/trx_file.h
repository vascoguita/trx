#ifndef TRX_TRX_FILE_H
#define TRX_TRX_FILE_H

typedef struct _trx_metadata {
    size_t size;
} trx_metadata;

typedef struct _trx_file {
    trx_metadata *metadata;
    void *content;
} trx_file;

trx_file *trx_file_init();
void trx_file_clear(trx_file *f);

int trx_file_save(trx_file *f, char *filename, size_t filename_size);
int trx_file_load(trx_file *f, char *filename, size_t filename_size);

#endif //TRX_TRX_FILE_H
