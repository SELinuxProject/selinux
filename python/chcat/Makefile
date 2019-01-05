# Installation directories.
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

.PHONY: all
all: chcat

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 chcat $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 644 chcat.8 $(DESTDIR)$(MANDIR)/man8/

clean:

indent:

relabel:

test:
