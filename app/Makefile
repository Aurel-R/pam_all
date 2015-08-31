
all : $(APP)

all-validate : all-validate.o utils.o crypto.o
	$(CC) -o $@ $^ $(APP_LIBS)  

all-validate.o : all-validate.c pam.h utils.h crypto.h
	$(CC) $(CFLAGS) -c $<

utils.o : utils.c utils.h
	$(CC) $(CFLAGS) -c $<

crypto.o : crypto.c crypto.h utils.h pam.h
	$(CC) $(CFLAGS) -c $<

clean :
	rm *.o $(APP)



