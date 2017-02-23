MODULE=pam_all.so
CC=gcc
MODULE_LIBS=-lpam -lssl -lcrypto 
CFLAGS=-DPAM_DEBUG -Wall

all : $(MODULE)


pam_all.so : pam_all.o pam.o prot.o ../crypto/crypto.o ../common/cma.o 
	$(CC) $(CFLAGS) -g -shared -o $@ $^ $(MODULE_LIBS)

pam_all.o : pam_all.c pam.h command_info.h prot.h ../crypto/crypto.h ../common/utils.h 
	$(CC) -fPIC $(CFLAGS) -c $<

pam.o : pam.c pam.h ../crypto/crypto.h ../common/utils.h prot.h 
	$(CC) -fPIC  $(CFLAGS) -c $<


../crypto/crypto.o : ../crypto/crypto.c ../crypto/crypto.h pam.h ../common/utils.h
	$(CC) -fPIC $(CFLAGS) -c $<
	mv crypto.o ../crypto/

prot.o : prot.c prot.h pam.h command_info.h ../crypto/crypto.h ../common/utils.h ../common/cma.h
	$(CC) -fPIC $(CFLAGS) -c $<


../common/cma.o : ../common/cma.c ../common/cma.h
	$(CC) -fPIC -Wall -lrt -c $<
	mv cma.o ../common/
	

clean :
	rm *.o $(MODULE) ../crypto/*.o ../common/*.o


