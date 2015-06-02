all : pam_shamir.so

#-lssl front -lcrypto ?
pam_shamir.so : pam_shamir.o utils.o app.o
	gcc -shared -o pam_shamir.so pam_shamir.o utils.o app.o -lpam -lcrypt -lcrypto -lssl

pam_shamir.o : pam_shamir.c config.h utils.h app.h 
	gcc -fPIC -Wall -c pam_shamir.c 

app.o : app.c app.h config.h utils.h
	gcc -fPIC -Wall -c app.c

utils.o : utils.c utils.h 
	gcc -fPIC -Wall -DDEBUG -c utils.c

clean : 
	rm *.o
