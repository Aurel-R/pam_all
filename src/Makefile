all : pam_shamir.so


pam_shamir.so : main.o
	gcc -shared -o pam_shamir.so main.o -lpam -lcrypt

main.o : main.c
	gcc -fPIC -Wall -DDEBUG -c main.c 

clean : 
	rm *.o
