all : pam_shamir.so


pam_shamir.so : pam_shamir.o
	gcc -shared -o pam_shamir.so pam_shamir.o -lpam -lcrypt

pam_shamir.o : pam_shamir.c
	gcc -fPIC -Wall -DDEBUG -c pam_shamir.c 

clean : 
	rm *.o
