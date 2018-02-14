# Installation directories.
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol

all: semodule_package semodule_unpackage

semodule_package:  semodule_package.o 

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 semodule_package $(DESTDIR)$(BINDIR)
	install -m 755 semodule_unpackage $(DESTDIR)$(BINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 semodule_package.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 semodule_unpackage.8 $(DESTDIR)$(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule_package semodule_unpackage *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

