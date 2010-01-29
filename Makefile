CFLAGS ?= -O0 -g
CFLAGS += -march=native
PROGS = sreadahead

VERSION = "1.0"

all: $(PROGS)

sreadahead: sreadahead.c Makefile
	gcc $(CFLAGS) -W sreadahead.c -o $@ -lpthread

clean:
	rm -f *~ $(PROGS)

install: all
	mkdir -p $(DESTDIR)/sbin
	mkdir -p $(DESTDIR)/var/lib/sreadahead/debugfs
	mkdir -p $(DESTDIR)/usr/share/man/man1
	install -p -m 755 $(PROGS) $(DESTDIR)/sbin
	install -p -m 644 sreadahead.1 $(DESTDIR)/usr/share/man/man1

dist:
	svn export . sreadahead-$(VERSION)
	tar cz --owner=root --group=root \
		-f sreadahead-$(VERSION).tar.gz sreadahead-$(VERSION)/
	rm -rf sreadahead-$(VERSION)
