#!/bin/sh

xtest --install-ta ../ta/
xtest --install-ta ../../manager/
xtest --install-ta ../../demo/ta/
xtest --install-ta ../../../optee_tui/manager/

../host/trx_setup