CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY = cc2fd8e5-8acc-4c3f-a7a8-d2b41cf2aeef

LDADD += $(TA_DEV_KIT_DIR)/lib/ibme.a
LDADD += $(TA_DEV_KIT_DIR)/lib/pbc.a
LDADD += $(TA_DEV_KIT_DIR)/lib/libgmp.a

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk