# set to -g if desired
DEBUG=

all:               libat.a

libat.a:  at.o
	$(AR) rv $@ $?

at.o: at.c at.h
	$(CC) $(DEBUG) -c -o $@ at.c

clean:
	rm -f *.a *.o
