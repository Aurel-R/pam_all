MODULE=pam_all.so
CC=gcc
MODULE_LIBS=-lpam
CFLAGS=-Wall -Wextra
#CFLAGS=-DPAM_DEBUG -Wall -Wextra
INSTALL=install
MODULE_PATH:=`find /lib -name "pam_unix.so" -exec dirname {} \;`

all : $(MODULE)


pam_all.so : pam_all.o pam.o protocol.o utils.o
	$(CC) $(CFLAGS) -shared -o $@ $^ $(MODULE_LIBS)

pam_all.o : pam_all.c  
	$(CC) -fPIC $(CFLAGS) -c $<

pam.o : pam.c  
	$(CC) -fPIC  $(CFLAGS) -c $<

protocol.o : protocol.c 
	$(CC) -fPIC $(CFLAGS) -c $<

utils.o : utils.c
	$(CC) -fPIC $(CFLAGS) -c $<

install: all
	$(INSTALL) -v -g 0 -o 0 -m 0644 $(MODULE) $(MODULE_PATH)

clean :
	rm *.o $(MODULE) 


