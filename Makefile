CC=gcc
CFLAGS=

LIBS=-ljansson -lssl -lcrypto

.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

psec-duo-auth: psec-duo-auth.o libduo/libduo.a
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

libduo/configure:
	git submodule update --init

libduo/Makefile: libduo/configure
	cd libduo && ./configure

libduo/libduo.a: libduo/Makefile
	cd libduo && make libduo.a

.PHONY: clean distclean install libduo/libduo.a

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp -f psec-duo-auth $(DESTDIR)/usr/bin/

clean:
	rm -f *.o *~
	test ! -f libduo/Makefile || (cd libduo && make clean)

distclean: clean
	test ! -f libduo/Makefile || (cd libduo && make distclean)
