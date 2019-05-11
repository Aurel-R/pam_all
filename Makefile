MODULE_DIR=./module
APP_DIR=./all-validate
INSTALL=install
MAN_PATH=/usr/share/man/man8/
MODULE_DOC=./doc/pam_all.8
APP_DOC=./doc/all-validate.8

all: pam_all app

pam_all:
	@(cd $(MODULE_DIR) && $(MAKE))
app:
	@(cd $(APP_DIR) && $(MAKE))

install: all 
	@(cd $(MODULE_DIR) && $(MAKE) $@)
	@(cd $(APP_DIR) && $(MAKE) $@)
	$(INSTALL) -v -g 0 -o 0 -m 0644 $(MODULE_DOC) $(MAN_PATH)
	gzip -f $(MAN_PATH)pam_all.8
	$(INSTALL) -v -g 0 -o 0 -m 0644 $(APP_DOC) $(MAN_PATH)
	gzip -f $(MAN_PATH)all-validate.8
	# add 'mandb' if necessary	

clean:
	@(cd $(MODULE_DIR) && $(MAKE) $@)
	@(cd $(APP_DIR) && $(MAKE) $@)
	


