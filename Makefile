# $@ : Target name (liblwp.a, lwp.o, numbersmain, etc.)
# $< : First dependency
all: liblwp.a lwp.o

liblwp.a: lwp.o
	ar rcs $@ lwp.o
	ranlib $@

lwp.o: lwp.c lwp.h
	gcc -std=gnu99 -Wall -Werror -m32 -g -c -o $@ $<

clean:
	rm -f *.a *.o *.s *.out *.dSYM .DS_Store