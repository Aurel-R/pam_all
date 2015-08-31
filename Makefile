export DEBUG=yes

export CC=gcc
export CFLAGS=-Wall
export MODULE=pam_all.so
export MODULE_LIBS=-lpam -lcrypt -lcrypto -lssl
export APP=all-validate
export APP_LIBS=-lpam -lpam_misc -lcrypto -lssl

MODULE_DIR=src
MODULE_EXEC=$(MODULE_DIR)/$(MODULE)
APP_DIR=app
APP_EXEC=$(APP_DIR)/$(APP)
MAN_PATH=/usr/share/man/man8/
SYS_MODULE_DIR=/etc/security/pam_all.d
SYS_USERSKEY_DIR=/etc/security/pam_all.d/users
SYS_CMD_DIR=/var/lib/pam_all
SYS_TMP_DIR=/var/lib/pam_all/tmp
INSTALL=install
INSTALL_OPT=-v -g 0 -o 0
MODULE_DOC=doc/pam_all.8
APP_DOC=doc/all-validate.8
#until configure file...
ARCH:=/lib/`ls /lib | grep gnu`
SUDO_PLUGIN_PATH=/usr/local/libexec/sudo
SUDO_PLUGIN_PATH_1=/usr/lib/sudo
SUDO_PLUGIN=shared.so
BIN_PATH=/usr/bin/


all : $(MODULE_EXEC) $(APP_EXEC)
module : $(MODULE_EXEC)
app : $(APP_EXEC)


$(MODULE_EXEC) : 
	@(cd $(MODULE_DIR) && $(MAKE))

$(APP_EXEC) : 
	@(cd $(APP_DIR) && $(MAKE))

install : all install-doc install-binaries
	pg INSTALL	


install-doc :
	$(INSTALL) $(INSTALL_OPT) -m 0644 $(MODULE_DOC) $(MAN_PATH)
	gzip -f $(MAN_PATH)pam_all.8
	$(INSTALL) $(INSTALL_OPT) -m 0644 $(APP_DOC) $(MAN_PATH)
	gzip -f $(MAN_PATH)all-validate.8
	# add 'mandb' if necessary	

install-binaries : install-dir
	$(INSTALL) $(INSTALL_OPT) -m 0644 $(MODULE_DIR)/$(MODULE) $(ARCH)/security/
	if [ -d $(SUDO_PLUGIN_PATH) ]; then ln -s -f $(ARCH)/security/$(MODULE) $(SUDO_PLUGIN_PATH)/$(SUDO_PLUGIN); fi
	if [ -d $(SUDO_PLUGIN_PATH_1) ]; then ln -s -f $(ARCH)/security/$(MODULE) $(SUDO_PLUGIN_PATH_1)/$(SUDO_PLUGIN); fi
	$(INSTALL) $(INSTALL_OPT) $(APP_DIR)/$(APP) $(BIN_PATH) 

install-dir :
	$(INSTALL) $(INSTALL_OPT) -d $(SYS_MODULE_DIR)
	$(INSTALL) $(INSTALL_OPT) -d $(SYS_USERSKEY_DIR)
	$(INSTALL) $(INSTALL_OPT) -m 0700 -d $(SYS_CMD_DIR)
	$(INSTALL) $(INSTALL_OPT) -m 0700 -d $(SYS_TMP_DIR)


clean :
	@(cd $(MODULE_DIR) && $(MAKE) $@)
	@(cd $(APP_DIR) && $(MAKE) $@)
 

