#!/bin/sh

cp $(dirname $0)/../manager/*.ta /lib/optee_armtz/.
cp $(dirname $0)/../demo/ta/*.ta /lib/optee_armtz/.

$(dirname $0)/../setup/trx_setup \
    $(dirname $0)/../trusted_authority/param.ibme \
    $(dirname $0)/../trusted_authority/mpk.ibme \
    $(dirname $0)/../trusted_authority/ek.ibme \
    $(dirname $0)/../trusted_authority/dk.ibme