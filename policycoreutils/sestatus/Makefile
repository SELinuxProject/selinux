# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LIBDIR ?= $(PREFIX)/lib

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include -D_FILE_OFFSET_BITS=64
LDLIBS = -lselinux -L$(LIBDIR)

all: sestatus

sestatus:  sestatus.o 

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	[ -d $(MANDIR)/man5 ] || mkdir -p $(MANDIR)/man5
	-mkdir -p $(SBINDIR)
	install -m 755 sestatus $(SBINDIR)
	install -m 644 sestatus.8 $(MANDIR)/man8
	install -m 644 sestatus.conf.5 $(MANDIR)/man5
	-mkdir -p $(ETCDIR)
	install -m 644 sestatus.conf $(ETCDIR)

clean:
	rm -f sestatus *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
