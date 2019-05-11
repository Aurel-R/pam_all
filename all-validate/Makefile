APP=all-validate
CC=gcc
LDFLAGS=-lpam -lpam_misc
CFLAGS=-std=gnu11 -Wall -Wextra
INSTALL=install
BIN_PATH=/usr/bin/

all : $(APP)

$(APP) : all-validate.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install: all
	$(INSTALL) -v -g 0 -o 0 -m 0755 $(APP) $(BIN_PATH) 

clean : 
	rm $(APP)

