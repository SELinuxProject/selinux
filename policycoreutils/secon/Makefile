# secon tool - command-line context
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

WARNS=-Werror -W -Wall -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -Wfloat-equal
VERSION = $(shell cat ../VERSION)
CFLAGS ?= $(WARNS) -O1
override CFLAGS += -DVERSION=\"$(VERSION)\" -I$(INCLUDEDIR) 
LDLIBS = -lselinux -L$(LIBDIR)

all: secon

secon: secon.o 

install-nogui: install

install: all
	install -m 755 secon $(BINDIR);

	test -d $(MANDIR)/man1 || install -m 755 -d $(MANDIR)/man1
	install -m 644 secon.1 $(MANDIR)/man1

relabel:
	/sbin/restorecon $(BINDIR)/secon

clean:
	rm -f *.o core* secon *~ *.bak

indent:
	../../scripts/Lindent $(wildcard *.[ch])

bare: clean

.PHONY: clean bare
