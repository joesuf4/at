all:               libat.a

libat.a:  at.o
	$(AR) rv $@ $?

clean:
	rm -f *.a *.o
