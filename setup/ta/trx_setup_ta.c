#include <tee_internal_api.h>
#include <string.h>
#include <trx_setup_ta.h>
#include <trx/trx.h>
#include <tui/tui.h>

//FIXME trusted authority should do this

#include <ibme/ibme.h>

static char *param_str = (char *) "type a\nq 87807107996633125224377819847540498158068831994142082110286533992664756308"
                                  "80222957078625179422662221423155858769582317459277713367317481324925129998224791\nh "
                                  "120160122648911460793888213667405342048029544012513118229196151310472072893597045311"
                                  "02844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 15"
                                  "9\nexp1 107\nsign1 1\nsign0 1";

//FIXME trusted authority should do this

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
    //FIXME trusted authority should do this
    pairing_t pairing;
    MKP *mkp;
    EK *ek;
    DK *dk;
    char *mpk_str;
    char *ek_str;
    char *dk_str;
    const char *id = "Alice";
    size_t id_size, mpk_str_size, ek_str_size, dk_str_size;

    id_size = strlen(id) + 1;
    //FIXME trusted authority should do this

    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TUI->setup("10.0.2.2", 9000);
    if(res != TEE_SUCCESS) {
        EMSG("TUI failed to setup with code 0x%x", res);
        return res;
    }

    //FIXME trusted authority should do this
    if(1 == pairing_init_set_str(pairing, param_str)) {
        return TEE_ERROR_GENERIC;
    }
    if(1 == MKP_init(pairing, &mkp)) {
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_setup(mkp)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == EK_init(pairing, &ek)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_sk_gen(pairing, mkp->msk, (unsigned char *)id, id_size, ek)) {
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == DK_init(pairing, &dk)) {
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_rk_gen(mkp->msk, (unsigned char *)id, id_size, dk)) {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if((mpk_str_size = MPK_snprint(NULL, 0, mkp->mpk) + 1) < 1) {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(!(mpk_str = (char *) malloc(mpk_str_size))) {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(mpk_str_size != (size_t)(MPK_snprint(mpk_str, mpk_str_size , mkp->mpk) + 1)) {
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if((ek_str_size = EK_snprint(NULL, 0, ek) + 1) < 1) {
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(!(ek_str = (char *) malloc(ek_str_size))) {
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(ek_str_size != (size_t)(EK_snprint(ek_str, ek_str_size , ek) + 1)) {
        free(ek_str);
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if((dk_str_size = DK_snprint(NULL, 0, dk) + 1) < 1) {
        free(ek_str);
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(!(dk_str = (char *) malloc(dk_str_size))) {
        free(ek_str);
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(dk_str_size != (size_t)(DK_snprint(dk_str, dk_str_size , dk) + 1)) {
        free(dk_str);
        free(ek_str);
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    //FIXME trusted authority should do this

    res = trx_setup(param_str, strlen(param_str) + 1, mpk_str, mpk_str_size, ek_str, ek_str_size, dk_str, dk_str_size);
    if(res != TEE_SUCCESS) {
        DMSG("trx_setup failed with code 0x%x", res);
        free(dk_str);
        free(ek_str);
        free(mpk_str);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    free(dk_str);
    free(ek_str);
    free(mpk_str);
    DK_clear(dk);
    EK_clear(ek);
    MKP_clear(mkp);
    pairing_clear(pairing);
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