#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <trx_demo_ta.h>
#include <trx/trx.h>
#include <tui/tui.h>

#include "trx_demo_private.h"

char *cipher = NULL;
size_t cipher_size = 0;
char *dir = NULL;
size_t dir_size;

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

TEE_Result share(trx_handle handle)
{
    TEE_Result res;
    char input[100], *id = NULL, *mount_point = NULL, *label = NULL, *data = NULL;
    size_t input_size, id_size, mount_point_size, label_size, data_size;

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
    res = TUI->input("Enter label: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    label = strdup(input);
    label_size = strlen(id) + 1;
    
    data_size = 1500;
    if (!(data = malloc(data_size)))
    {
        DMSG("malloc failed");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    res = trx_share(handle, (unsigned char *)id, id_size, mount_point, mount_point_size, label, label_size, data, &data_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_share failed with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }

    memcpy(&cipher_size, data, sizeof(size_t));
    if(cipher)
    {
        free(cipher);
    }
    if (!(cipher = malloc(cipher_size)))
    {
        DMSG("malloc failed");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    memcpy(cipher, data + sizeof(size_t), cipher_size);
    res = TUI->print(cipher);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to print with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    memcpy(&dir_size, data + sizeof(size_t) + cipher_size, sizeof(size_t));
    if(dir)
    {
        free(dir);
    }
    if (!(dir = malloc(dir_size)))
    {
        DMSG("malloc failed");
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    memcpy(dir, data + sizeof(size_t) + cipher_size + sizeof(size_t), dir_size);

    res = TUI->print(dir);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to print with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }

out:
    free(data);
    free(mount_point);
    free(id);
    free(label);
    return res;
}

TEE_Result mount(trx_handle handle)
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
    res = TUI->input("Enter sender ID: ", input, input_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to input with code 0x%x", res);
        res = TEE_ERROR_GENERIC;
        goto out;
    }
    id = strdup(input);
    id_size = strlen(id) + 1;
    res = trx_mount(handle, (unsigned char *)id, id_size, dir, dir_size, mount_point, mount_point_size, cipher, cipher_size);
    if (res != TEE_SUCCESS)
    {
        DMSG("trx_mount failed with code 0x%x", res);
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

    if(dir)
    {
        free(dir);
    }

    if(cipher)
    {
        free(cipher);
    }

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