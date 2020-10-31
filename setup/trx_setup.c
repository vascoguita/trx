#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <trx_manager_ta.h>

#include <trx_setup.h>

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;
    FILE *fp;
    char *param_str, *mpk_str, *ek_str, *dk_str;
    size_t param_str_size, mpk_str_size, ek_str_size, dk_str_size;

    if (argc >= 5) {
        if(!(fp = fopen(argv[1], "r"))) {
            errx(1, "Setup failed: error opening file \"%s\".", argv[1]);
        }
        fseek(fp, 0, SEEK_END);
        param_str_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        param_str = malloc(param_str_size);
        fread(param_str, 1, param_str_size, fp);
        fclose(fp);

        if(!(fp = fopen(argv[2], "r"))) {
            free(param_str);
            errx(1, "Setup failed: error opening file \"%s\".", argv[2]);
        }
        fseek(fp, 0, SEEK_END);
        mpk_str_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        mpk_str = malloc(mpk_str_size);
        fread(mpk_str, 1, mpk_str_size, fp);
        fclose(fp);

        if(!(fp = fopen(argv[3], "r"))) {
            free(param_str);
            free(mpk_str);
            errx(1, "Setup failed: error opening file \"%s\".", argv[3]);
        }
        fseek(fp, 0, SEEK_END);
        ek_str_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        ek_str = malloc(ek_str_size);
        fread(ek_str, 1, ek_str_size, fp);
        fclose(fp);

        if(!(fp = fopen(argv[4], "r"))) {
            free(param_str);
            free(mpk_str);
            free(ek_str);
            errx(1, "Setup failed: error opening file \"%s\".", argv[4]);
        }
        fseek(fp, 0, SEEK_END);
        dk_str_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        dk_str = malloc(dk_str_size);
        fread(dk_str, 1, dk_str_size, fp);
        fclose(fp);

        prepare_tee_session(&ctx, &sess);
        if(trx_setup(&sess, param_str, param_str_size,
                     mpk_str, mpk_str_size, ek_str, ek_str_size, dk_str, dk_str_size) != 0) {
            printf("trx_setup failed");
            free(param_str);
            free(mpk_str);
            free(ek_str);
            free(dk_str);
            terminate_tee_session(&ctx, &sess);
            return 1;
        }
        free(param_str);
        free(mpk_str);
        free(ek_str);
        free(dk_str);
        terminate_tee_session(&ctx, &sess);
    } else {
        errx(1, "Setup requires two arguments.\n"
                "Please run: trx_setup <path/to/param.ibme> <path/to/mpk.ibme> <path/to/ek.ibme> <path/to/dk.ibme>");
    }
    return 0;
}

void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess) {
    TEEC_UUID uuid = TA_TRX_MANAGER_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    }

    res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
    }
}

void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess) {
    TEEC_CloseSession(sess);
    TEEC_FinalizeContext(ctx);
}


int trx_setup(TEEC_Session *sess,
              char *param_str, size_t param_str_size,
              char *mpk_str, size_t mpk_str_size,
              char *ek_str, size_t ek_str_size,
              char *dk_str, size_t dk_str_size) {
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT);

    op.params[0].tmpref.buffer = param_str;
    op.params[0].tmpref.size = param_str_size;
    op.params[1].tmpref.buffer = mpk_str;
    op.params[1].tmpref.size = mpk_str_size;
    op.params[2].tmpref.buffer = ek_str;
    op.params[2].tmpref.size = ek_str_size;
    op.params[3].tmpref.buffer = dk_str;
    op.params[3].tmpref.size = dk_str_size;

    res = TEEC_InvokeCommand(sess, TA_TRX_MANAGER_CMD_SETUP, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return 1;
    }
    return 0;
}