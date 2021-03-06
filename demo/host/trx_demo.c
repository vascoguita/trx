#include <err.h>
#include <stdio.h>

#include <tee_client_api.h>

#include <trx_demo_ta.h>

#include <trx_demo.h>

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;

    prepare_tee_session(&ctx, &sess);

    terminate_tee_session(&ctx, &sess);

    return 0;
}

void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess) {
    TEEC_UUID uuid = TA_TRX_DEMO_UUID;
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