# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)

all: semodule_deps

semodule_deps:  semodule_deps.o $(LIBSEPOLA)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 semodule_deps $(BINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 644 semodule_deps.8 $(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule_deps *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

