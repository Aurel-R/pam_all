MODULE=pam_all.so
CC=gcc
MODULE_LIBS=-lpam
CFLAGS=-DPAM_DEBUG -Wall -Wextra
#CFLAGS=-Wall -Wextra

all : $(MODULE)


pam_all.so : pam_all.o pam.o protocol.o utils.o
	$(CC) $(CFLAGS) -g -shared -o $@ $^ $(MODULE_LIBS)

pam_all.o : pam_all.c  
	$(CC) -fPIC $(CFLAGS) -c $<

pam.o : pam.c  
	$(CC) -fPIC  $(CFLAGS) -c $<

protocol.o : protocol.c 
	$(CC) -fPIC $(CFLAGS) -c $<

utils.o : utils.c
	$(CC) -fPIC $(CFLAGS) -c $<

clean :
	rm *.o $(MODULE) 


