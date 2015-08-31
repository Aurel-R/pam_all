ifeq ($(DEBUG), yes)
	VERBOSE=-DDEBUG
else
	VERBOSE=
endif


all : $(MODULE)


pam_all.so : pam_all.o pam.o utils.o crypto.o
	$(CC) -shared -o $@ $^ $(MODULE_LIBS)

pam_all.o : pam_all.c pam.h utils.h crypto.h
	$(CC) -fPIC $(CFLAGS) $(VERBOSE) -c $<

pam.o : pam.c pam.h utils.h crypto.h
	$(CC) -fPIC $(CFLAGS) -c $<

crypto.o : crypto.c crypto.h pam.h utils.h
	$(CC) -fPIC $(CFLAGS) -c $<


utils.o : utils.c utils.h
	$(CC) -fPIC $(CFLAGS) -c $<


clean :
	rm *.o $(MODULE) 


