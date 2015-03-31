all : pam_shamir.so


pam_shamir.so : main.o
	gcc -shared -o pam_shamir.so main.o -lpam

main.o : main.c
	gcc -fPIC -c main.c 

clean : 
	rm *.o
