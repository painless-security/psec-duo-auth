CC=gcc
CFLAGS=

LIBS=-lduo -ljansson

.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

psec-duo-auth: psec-duo-auth.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp -f psec-duo-auth $(DESTDIR)/usr/bin/

clean:
	rm -f *.o *~
