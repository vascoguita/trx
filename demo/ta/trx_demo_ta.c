#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <trx_demo_ta.h>
#include <trx/trx.h>
#include <tui/tui.h>

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("has been called");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx)
{
    uint32_t exp_param_types;
    TEE_Result res;
    char input[100], *path, *data, *id;
    size_t input_size, path_size, data_size, id_size;
    uint8_t *cpy_ptr;
    size_t left;
    long unsigned int n_pobjs, i;
    trx_handle handle;

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
    if(res != TEE_SUCCESS)
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
            res = TUI->input("Enter path: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            res = TUI->input("Enter data: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                free(path);
                return res;
            }
            data = strdup(input);
            data_size = strlen(data) + 1;
            res = trx_write(handle, path, path_size, data, data_size);
            if (res != TEE_SUCCESS)
            {
                DMSG("trx_write failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            free(data);
        }
        else if (strncmp(input, "read", strlen("read")) == 0)
        {
            res = TUI->input("Enter path: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            data = NULL;
            data_size = 0;
            res = trx_read(handle, path, path_size, data, &data_size);
            if (res != TEE_ERROR_SHORT_BUFFER)
            {
                free(path);
                DMSG("trx_read failed with code 0x%x", res);
                return TEE_ERROR_GENERIC;
            }
            if (!(data = malloc(data_size)))
            {
                free(path);
                DMSG("malloc failed");
                return TEE_ERROR_GENERIC;
            }
            res = trx_read(handle, path, path_size, data, &data_size);
            if (res != TEE_SUCCESS)
            {
                DMSG("trx_read failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            res = TUI->print(data);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to print with code 0x%x", res);
                free(data);
                return res;
            }
            free(data);
        }
        else if (strncmp(input, "list", strlen("list")) == 0)
        {
            data = NULL;
            data_size = 0;
            res = trx_list(handle, data, &data_size);
            if (res != TEE_ERROR_SHORT_BUFFER)
            {
                DMSG("trx_list failed with code 0x%x", res);
                return TEE_ERROR_GENERIC;
            }
            if (!(data = malloc(data_size)))
            {
                DMSG("malloc failed");
                return TEE_ERROR_GENERIC;
            }
            res = trx_list(handle, data, &data_size);
            if (res != TEE_SUCCESS)
            {
                DMSG("trx_list failed with code 0x%x", res);
                free(data);
                return TEE_ERROR_GENERIC;
            }

            cpy_ptr = (uint8_t *)data;
            left = data_size;
            if (left < sizeof(long unsigned int))
            {
                EMSG("failed checking size of \"data\" buffer");
                return TEE_ERROR_GENERIC;
            }
            memcpy(&n_pobjs, cpy_ptr, sizeof(long unsigned int));
            cpy_ptr += sizeof(long unsigned int);
            left -= sizeof(long unsigned int);
            DMSG("Fetching %lu pobjs paths", n_pobjs);
            for (i = 0; i < n_pobjs; i++)
            {
                if (left < sizeof(size_t))
                {
                    EMSG("failed checking size of \"data\" buffer");
                    return TEE_ERROR_GENERIC;
                }
                memcpy(&path_size, cpy_ptr, sizeof(size_t));
                cpy_ptr += sizeof(size_t);
                left -= sizeof(size_t);

                DMSG("size of pobj path %zu", path_size);
                if (left < path_size)
                {
                    EMSG("failed checking size of \"data\" buffer");
                    return TEE_ERROR_GENERIC;
                }
                if (!(path = malloc(path_size)))
                {
                    EMSG("failed calling function \'malloc\'");
                    return TEE_ERROR_GENERIC;
                }
                memcpy(path, cpy_ptr, path_size);
                cpy_ptr += path_size;
                left -= path_size;

                DMSG("pobj path %path", path);
                res = TUI->print(path);
                if (res != TEE_SUCCESS)
                {
                    EMSG("Failed to print with code 0x%x", res);
                    free(path);
                    free(data);
                    return res;
                }
                free(path);
            }
            if (left != 0)
            {
                EMSG("failed checking size of \"data\" buffer");
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(data);
        }
        else if (strncmp(input, "mount", strlen("mount")) == 0)
        {
            res = TUI->input("Enter sender ID: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            id = strdup(input);
            id_size = strlen(id) + 1;
            res = TUI->input("Enter dirname: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                free(id);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            res = TUI->input("Enter mount point: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                free(id);
                free(path);
                return res;
            }
            data = strdup(input);
            data_size = strlen(data) + 1;
            res = trx_mount(handle, (unsigned char *)id, id_size, path, path_size, data, data_size);
            if (res != TEE_SUCCESS)
            {
                DMSG("trx_mount failed with code 0x%x", res);
                free(id);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(id);
            free(path);
            free(data);
        }
        else if (strncmp(input, "share", strlen("share")) == 0)
        {
            res = TUI->input("Enter mount point: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            res = TUI->input("Enter receiver ID: ", input, input_size);
            if (res != TEE_SUCCESS)
            {
                EMSG("Failed to input with code 0x%x", res);
                free(path);
                return res;
            }
            data = strdup(input);
            data_size = strlen(data) + 1;
            res = trx_share(handle, (unsigned char *)data, data_size, path, path_size);
            if (res != TEE_SUCCESS)
            {
                DMSG("trx_share failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            free(data);
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