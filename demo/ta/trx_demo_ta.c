#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <trx_demo_ta.h>
#include <trx/trx.h>
#include <trx_path.h>
#include <tui/tui.h>

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    TEE_Result res;
    path_list_head *lh;
    path_entry *e;
    char input[100], *path, *data;
    size_t input_size, path_size, data_size, result;
    int status;

    input_size = 100;

    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    while(1) {
        res = TUI->input("Enter command: ", input, input_size);
        if(res != TEE_SUCCESS) {
            EMSG("Failed to input with code 0x%x", res);
            return res;
        }
        if(strncmp(input, "write", strlen("write")) == 0) {
            res = TUI->input("Enter path: ", input, input_size);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            res = TUI->input("Enter data: ", input, input_size);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to input with code 0x%x", res);
                free(path);
                return res;
            }
            data = strdup(input);
            data_size = strlen(data) + 1;
            res = trx_write(path, path_size, data, data_size);
            if(res != TEE_SUCCESS) {
                DMSG("trx_write failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            free(data);
        } else if(strncmp(input, "read", strlen("read")) == 0) {
            res = TUI->input("Enter path: ", input, input_size);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            data = NULL;
            data_size = 0;
            res = trx_read(path, path_size, data, &data_size);
            if (res != TEE_SUCCESS) {
                free(path);
                DMSG("trx_read failed with code 0x%x", res);
                return TEE_ERROR_GENERIC;
            }
            if(!(data = malloc(data_size))) {
                free(path);
                DMSG("malloc failed");
                return TEE_ERROR_GENERIC;
            }
            res = trx_read(path, path_size, data, &data_size);
            if (res != TEE_SUCCESS) {
                DMSG("trx_read failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            res = TUI->print(data);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to print with code 0x%x", res);
                free(data);
                return res;
            }
            free(data);
        } else if(strncmp(input, "list", strlen("list")) == 0) {
            if(!(lh = trx_path_list_init())) {
                DMSG("trx_list failed with code 0x%x", res);
                return TEE_ERROR_GENERIC;
            }
            res = trx_list(lh);
            if (res != TEE_SUCCESS) {
                DMSG("trx_list failed with code 0x%x", res);
                trx_path_list_clear(lh);
                return TEE_ERROR_GENERIC;
            }
            result = 0;
            if((status = snprintf(NULL, 0, "%-10s | %-10s", "path", "bytes")) < 0) {
                DMSG("snprintf failed");
                trx_path_list_clear(lh);
            }
            data_size = status + 1;
            if(!(data = malloc(data_size))) {
                DMSG("malloc failed");
                trx_path_list_clear(lh);
            }
            if(snprintf(data, data_size, "%-10s | %-10s", "path", "bytes") < 0) {
                DMSG("snprintf failed");
                free(data);
                trx_path_list_clear(lh);
            }
            result += status;
            SLIST_FOREACH(e, lh, _path_entries) {
                if((status = snprintf(NULL, 0, "\n%-10s | %-10zu", e->path->path, e->path->data_size)) < 0) {
                    DMSG("snprintf failed");
                    free(data);
                    trx_path_list_clear(lh);
                }
                data_size += status;
                if(!(data = realloc(data, data_size))) {
                    DMSG("malloc failed");
                    free(data);
                    trx_path_list_clear(lh);
                }
                if(snprintf(data + result, data_size - result, "\n%-10s | %-10zu", e->path->path, e->path->data_size) < 0) {
                    DMSG("snprintf failed");
                    free(data);
                    trx_path_list_clear(lh);
                }
                result += status;
            }
            trx_path_list_clear(lh);
            res = TUI->print(data);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to print with code 0x%x", res);
                free(data);
                trx_path_list_clear(lh);
                return res;
            }
            free(data);
        } else if(strncmp(input, "mount", strlen("mount")) == 0) {
            res = TUI->input("Enter dirname: ", input, input_size);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to input with code 0x%x", res);
                return res;
            }
            path = strdup(input);
            path_size = strlen(path) + 1;
            res = TUI->input("Enter mount_point: ", input, input_size);
            if(res != TEE_SUCCESS) {
                EMSG("Failed to input with code 0x%x", res);
                free(path);
                return res;
            }
            data = strdup(input);
            data_size = strlen(data) + 1;
            res = trx_mount(path, path_size, data, data_size);
            if(res != TEE_SUCCESS) {
                DMSG("trx_mount failed with code 0x%x", res);
                free(path);
                free(data);
                return TEE_ERROR_GENERIC;
            }
            free(path);
            free(data);
        } else if(strncmp(input, "share", strlen("share")) == 0) {

        } else if(strncmp(input, "exit", strlen("exit")) == 0) {
            break;
        }
    }

	return res;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    (void)&params;
    (void)&cmd;
    (void)&param_types;
    (void)&sess_ctx;

    return TEE_ERROR_NOT_SUPPORTED;
}