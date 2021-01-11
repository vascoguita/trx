#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <trx_demo_ta.h>
#include <trx/trx.h>
#include <tui/tui.h>

#include "trx_demo_private.h"

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("has been called");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");
}

TEE_Result write(trx_handle handle)
{
    TEE_Result res;
    char input[100], *path = NULL, *data = NULL;
    size_t input_size, path_size, data_size;

    input_size = 100;

    res = TUI->input("Enter path: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    path = strdup(input);
    path_size = strlen(path) + 1;
    res = TUI->input("Enter data: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    data = strdup(input);
    data_size = strlen(data) + 1;
    res = trx_write(handle, path, path_size, data, data_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_write failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    free(path);
    free(data);
    return res;
}

TEE_Result read(trx_handle handle)
{
    TEE_Result res;
    char input[100], *path = NULL, *data = NULL;
    size_t input_size, path_size, data_size;

    input_size = 100;

    res = TUI->input("Enter path: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    path = strdup(input);
    path_size = strlen(path) + 1;
    res = trx_read(handle, path, path_size, NULL, &data_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        DMSG("trx_read failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(data = malloc(data_size)))
    {
        DMSG("malloc failed");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_read(handle, path, path_size, data, &data_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_read failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = TUI->print(data);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to print with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    free(data);
    free(path);
    return res;
}

TEE_Result list(trx_handle handle)
{
    TEE_Result res;
    char *data = NULL, *paths = NULL;
    size_t data_size = 0, path_size, left, paths_size = 0;
    uint8_t *cpy_ptr;
    long unsigned int n_paths, i;

    res = trx_list(handle, data, &data_size);
    if (res != TEE_ERROR_SHORT_BUFFER)
    {
        DMSG("trx_list failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    if (!(data = malloc(data_size)))
    {
        DMSG("malloc failed");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_list(handle, data, &data_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_list failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    cpy_ptr = (uint8_t *)data;
    left = data_size;
    if (left < sizeof(long unsigned int))
    {
        EMSG("failed checking size of \"data\" buffer");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    memcpy(&n_paths, cpy_ptr, sizeof(long unsigned int));
    cpy_ptr += sizeof(long unsigned int);
    left -= sizeof(long unsigned int);

    for (i = 0; i < n_paths; i++)
    {
        if (left < sizeof(size_t))
        {
            EMSG("failed checking size of \"data\" buffer");
            res = TEE_ERROR_GENERIC;
            goto out;
        }
        memcpy(&path_size, cpy_ptr, sizeof(size_t));
        cpy_ptr += sizeof(size_t);
        left -= sizeof(size_t);

        if (left < path_size)
        {
            EMSG("failed checking size of \"data\" buffer");
            res = TEE_ERROR_GENERIC;
            goto out;
        }

        if (paths)
        {
            paths[paths_size - 1] = '\n';
        }

        paths_size += path_size;
        if (!(paths = realloc(paths, paths_size)))
        {
            EMSG("Failed to print with code 0x%x", res);
            res = TEE_ERROR_GENERIC;
            goto out;
        }

        memcpy(paths + paths_size - path_size, cpy_ptr, path_size);
        cpy_ptr += path_size;
        left -= path_size;
    }
    if (left != 0)
    {
        EMSG("failed checking size of \"data\" buffer");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    
    if(paths_size)
    {
        res = TUI->print(paths);
        if (res != TEE_SUCCESS)
        {
            EMSG("Failed to print with code 0x%x", res);
            res = TEE_ERROR_GENERIC;
            goto out;
        }
    }
out:
    free(paths);
    free(data);
    return res;
}

TEE_Result mount(trx_handle handle)
{
    TEE_Result res;
    char input[100], *id = NULL, *mount_point = NULL, *dirname = NULL;
    size_t input_size, id_size, mount_point_size, dirname_size;

    input_size = 100;

    res = TUI->input("Enter dirname: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    dirname = strdup(input);
    dirname_size = strlen(dirname) + 1;
    res = TUI->input("Enter mount point: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    mount_point = strdup(input);
    mount_point_size = strlen(mount_point) + 1;
    res = TUI->input("Enter sender ID: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    id = strdup(input);
    id_size = strlen(id) + 1;
    res = trx_mount(handle, (unsigned char *)id, id_size, dirname, dirname_size, mount_point, mount_point_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_mount failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
out:
    free(mount_point);
    free(dirname);
    free(id);
    return res;
}

TEE_Result share(trx_handle handle)
{
    TEE_Result res;
    char input[100], *id = NULL, *mount_point = NULL;
    size_t input_size, id_size, mount_point_size;

    input_size = 100;

    res = TUI->input("Enter mount point: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    mount_point = strdup(input);
    mount_point_size = strlen(mount_point) + 1;
    res = TUI->input("Enter receiver ID: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    id = strdup(input);
    id_size = strlen(id) + 1;
    res = trx_share(handle, (unsigned char *)id, id_size, mount_point, mount_point_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_share failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    free(mount_point);
    free(id);
    return res;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx)
{
    uint32_t exp_param_types;
    TEE_Result res;
    trx_handle handle;
    char input[100];
    size_t input_size;

    input_size = 100;

    (void)&params;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = trx_handle_init(&handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("trx_handle_init failed with code 0x%x", res);
        return res;
    }
    while (1)
    {
        res = TUI->input("Enter command: ", input, input_size);
        if (res != TEE_SUCCESS)
        {
            EMSG("Failed to input with code 0x%x", res);
            return res;
        }
        if (strncmp(input, "write", strlen("write")) == 0)
        {
            res = write(handle);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed calling function write with code 0x%x", res);
                return res;
            }
        }
        else if (strncmp(input, "read", strlen("read")) == 0)
        {
            res = read(handle);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed calling function read with code 0x%x", res);
                return res;
            }
        }
        else if (strncmp(input, "list", strlen("list")) == 0)
        {
            res = list(handle);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed calling function list with code 0x%x", res);
                return res;
            }
        }
        else if (strncmp(input, "mount", strlen("mount")) == 0)
        {
            res = mount(handle);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed calling function mount with code 0x%x", res);
                return res;
            }
        }
        else if (strncmp(input, "share", strlen("share")) == 0)
        {
            res = share(handle);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed calling function share with code 0x%x", res);
                return res;
            }
        }
        else if (strncmp(input, "exit", strlen("exit")) == 0)
        {
            break;
        }
    }
    trx_handle_clear(handle);

    return res;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4])
{
    (void)&params;
    (void)&cmd;
    (void)&param_types;
    (void)&sess_ctx;

    return TEE_ERROR_NOT_SUPPORTED;
}