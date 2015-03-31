all : shamir.so


shamir.so : main.o
	gcc -shared -o shamir.so main.o -lpam

main.o : main.c
	gcc -fPIC -c main.c 
