ROOT							?= $(CURDIR)
SETUP_ROOT						?= $(ROOT)/setup
API_ROOT						?= $(ROOT)/api
MANAGER_ROOT					?= $(ROOT)/manager
DEMO_ROOT						?= $(ROOT)/demo

.PHONY: all
all: api

.PHONY: api
api: manager
	$(MAKE) -C $(API_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: manager
manager:
	$(MAKE) -C $(MANAGER_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: install
install:
	mv $(API_ROOT)/trx.a $(TA_DEV_KIT_DIR)/lib/. && \
	mkdir -p $(TA_DEV_KIT_DIR)/include/trx && \
	cp $(API_ROOT)/include/* $(TA_DEV_KIT_DIR)/include/trx/.

.PHONY: setup
setup:
	$(MAKE) -C $(SETUP_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TEEC_EXPORT=$(TEEC_EXPORT) \
		--no-builtin-variables

.PHONY: demo
demo:
	$(MAKE) -C $(DEMO_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TEEC_EXPORT=$(TEEC_EXPORT) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: clean
clean: api_clean manager_clean

.PHONY: api_clean
api_clean:
	$(MAKE) -C $(API_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: manager_clean
manager_clean:
	$(MAKE) -C $(MANAGER_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: uninstall
uninstall:
	rm -r $(TA_DEV_KIT_DIR)/include/trx; \
	rm $(TA_DEV_KIT_DIR)/lib/trx.a;

.PHONY: setup_clean
setup_clean:
	$(MAKE) -C $(SETUP_ROOT) clean

.PHONY: demo_clean
demo_clean:
	$(MAKE) -C $(DEMO_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)