#ifndef TRX_TRX_TA_H
#define TRX_TRX_TA_H

#include <ibme.h>
#define SETUP_CMD   "-s"
#define GEN_CMD     "-g"
#define HELP_CMD    "-h"

#define HELP_PROP   "Try \'trx_ta -h\' for more information."
#define HELP_INFO   "Commands:\n"                                                                               \
                    "\t" SETUP_CMD "\t"         "\t Setup Trusted Authority.\n"                                 \
                    "\t" GEN_CMD   " <id>\t"    "\t Generate IB-ME encryption and decryption keys for <id>.\n"  \
                    "\t" HELP_CMD  "\t"         "\t Print this help information.\n"

static char *param_str = "type a\nq 87807107996633125224377819847540498158068831994142082110286533992664756308802"
                         "22957078625179422662221423155858769582317459277713367317481324925129998224791\nh 120160"
                         "122648911460793888213667405342048029544012513118229196151310472072893597045311028448021"
                         "83906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107"
                         "\nsign1 1\nsign0 1";

int ta_setup(void);
int ta_gen(char *id);

#endif //TRX_TRX_TA_H
