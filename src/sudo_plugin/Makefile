all : shared.so


shared.so : shared.o
	gcc -shared -o shared.so shared.o

shared.o : shared.c
	gcc -fPIC -Wall -DDEBUG -c shared.c 

clean : 
	rm *.o
