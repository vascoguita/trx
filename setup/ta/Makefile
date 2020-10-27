CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY = 46b562e3-62a1-4104-a187-73fcb9f2bce2

LDADD += $(TA_DEV_KIT_DIR)/lib/trx.a
LDADD += $(TA_DEV_KIT_DIR)/lib/tui.a
LDADD += $(TA_DEV_KIT_DIR)/lib/ibme.a
LDADD += $(TA_DEV_KIT_DIR)/lib/pbc.a
LDADD += $(TA_DEV_KIT_DIR)/lib/libgmp.a

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
