all:               libat.a

libat.a:  at.c
	$(AR) rv $@ $?

clean:
	rm -f *.a *.o
