all : pam_shamir.so shared.so


pam_shamir.so : pam_shamir.o
	gcc -shared -o pam_shamir.so pam_shamir.o -lpam -lcrypt

pam_shamir.o : pam_shamir.c
	gcc -fPIC -Wall -DDEBUG -c pam_shamir.c 

shared.so : shared.o
	gcc -shared -o shared.so shared.o

shared.o :
	gcc -fPIC -Wall -DDEBUG -c shared.c

clean : 
	rm *.o
