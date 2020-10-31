#!/bin/sh

xtest --install-ta $(dirname $0)/../manager/
xtest --install-ta $(dirname $0)/../demo/ta/

$(dirname $0)/../setup/trx_setup \
    $(dirname $0)/../trusted_authority/param.ibme \
    $(dirname $0)/../trusted_authority/mpk.ibme \
    $(dirname $0)/../trusted_authority/ek.ibme \
    $(dirname $0)/../trusted_authority/dk.ibme