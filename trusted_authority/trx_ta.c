#include "trx_ta.h"
#include <ibme.h>

#include <stdio.h>
#include <string.h>
#include <err.h>

int main (int argc, char *argv[]) {
    if (argc >= 2) {
        if (strcmp(argv[1], SETUP_CMD) == 0) {
            if(ta_setup() != 0) {
                return 1;
            }
            return 0;
        } else if (strcmp(argv[1], HELP_CMD) == 0) {
            printf(HELP_INFO);
            return 0;
        } else if (strcmp(argv[1], GEN_CMD) == 0) {
            if (argc >= 3) {
                if(ta_gen(argv[2]) != 0) {
                    return 1;
                }
                return 0;
            } else {
                errx(1, "Option \'%s\' requires an argument.\n%s", argv[1], HELP_PROP);
            }
        } else {
            errx(1, "Unknown command \'%s\'.\n%s", argv[1], HELP_PROP);
        }
    } else {
        errx(1, "No command specified.\n%s", HELP_PROP);
    }
    return 0;
}

int ta_setup(void) {
    FILE *fp;
    pairing_t pairing;
    MKP *mkp;
    char *mpk_str, *msk_str;
    size_t mpk_str_len, msk_str_len;

    if(1 == pairing_init_set_str(pairing, param_str)) {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp)) {
        pairing_clear(pairing);
        return 1;
    }
    if(1 == setup(mkp)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if((mpk_str_len = MPK_snprint(NULL, 0, mkp->mpk)) < 0) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((mpk_str = (char *) malloc((mpk_str_len + 1) * sizeof(char))) == NULL) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(mpk_str_len != MPK_snprint(mpk_str, (mpk_str_len + 1) , mkp->mpk)) {
        free(mpk_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    fp = fopen("mpk.ibme", "w");
    fwrite(mpk_str, 1, mpk_str_len + 1, fp);
    fclose(fp);
    free(mpk_str);

    if((msk_str_len = MSK_snprint(NULL, 0, mkp->msk)) < 0) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((msk_str = (char *) malloc((msk_str_len + 1) * sizeof(char))) == NULL) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(msk_str_len != MSK_snprint(msk_str, (msk_str_len + 1) , mkp->msk)) {
        free(msk_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    fp = fopen("msk.ibme", "w");
    fwrite(msk_str, 1, msk_str_len + 1, fp);
    fclose(fp);
    free(msk_str);

    fp = fopen("param.ibme", "w");
    fwrite(param_str, 1, strlen(param_str) + 1, fp);
    fclose(fp);

    return 0;
}

int ta_gen(char *id) {
    FILE *fp;
    pairing_t pairing;
    MKP *mkp;
    EK *ek;
    DK *dk;
    char *mpk_str, *msk_str, *ek_str, *dk_str;
    size_t mpk_str_len, msk_str_len, ek_str_len, dk_str_len;

    if(1 == pairing_init_set_str(pairing, param_str)) {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp)) {
        pairing_clear(pairing);
        return 1;
    }

    fp = fopen("msk.ibme", "r");
    fseek(fp, 0, SEEK_END);
    msk_str_len = ftell(fp) - 1;
    fseek(fp, 0, SEEK_SET);
    msk_str = (char*)malloc((msk_str_len + 1) * sizeof(char));
    fread(msk_str, 1, msk_str_len + 1, fp);
    fclose(fp);

    if(0 == MSK_set_str(msk_str, msk_str_len + 1, mkp->msk)) {
        free(msk_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    free(msk_str);

    fp = fopen("mpk.ibme", "r");
    fseek(fp, 0, SEEK_END);
    mpk_str_len = ftell(fp) - 1;
    fseek(fp, 0, SEEK_SET);
    mpk_str = (char*)malloc((mpk_str_len + 1) * sizeof(char));
    fread(mpk_str, 1, mpk_str_len + 1, fp);
    fclose(fp);

    if(0 == MPK_set_str(mpk_str, mpk_str_len + 1, mkp->mpk)) {
        free(mpk_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    free(mpk_str);

    if(1 == EK_init(pairing, &ek)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == sk_gen(pairing, mkp->msk, (unsigned char *)id, strlen(id) + 1, ek)) {
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if((ek_str_len = EK_snprint(NULL, 0, ek)) < 0) {
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((ek_str = (char *) malloc((ek_str_len + 1) * sizeof(char))) == NULL) {
        EK_clear(ek);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(ek_str_len != EK_snprint(ek_str, (ek_str_len + 1) , ek)) {
        EK_clear(ek);
        free(ek_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    fp = fopen("ek.ibme", "w");
    fwrite(ek_str, 1, ek_str_len + 1, fp);
    fclose(fp);
    free(ek_str);
    EK_clear(ek);

    if(1 == DK_init(pairing, &dk)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == rk_gen(mkp->msk, (unsigned char *)id, strlen(id) + 1, dk)) {
        DK_clear(dk);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if((dk_str_len = DK_snprint(NULL, 0, dk)) < 0) {
        DK_clear(dk);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((dk_str = (char *) malloc((dk_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(dk_str_len != DK_snprint(dk_str, (dk_str_len + 1) , dk)) {
        DK_clear(dk);
        free(dk_str);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    fp = fopen("dk.ibme", "w");
    fwrite(dk_str, 1, dk_str_len + 1, fp);
    fclose(fp);
    free(dk_str);
    DK_clear(dk);
    MKP_clear(mkp);
    pairing_clear(pairing);

    fp = fopen("udid.ibme", "w");
    fwrite(id, 1, strlen(id) + 1, fp);
    fclose(fp);

    return 0;
}