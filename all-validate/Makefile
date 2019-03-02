#compile with std=gnu11

APP=all-validate
CC=gcc
LDFLAGS=-lpam -lpam_misc
CFLAGS=-std=gnu11 -Wall -Wextra

all : $(APP)

$(APP) : all-validate.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean : 
	rm *.o $(APP)

