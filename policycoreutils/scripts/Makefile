# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
USRSBINDIR ?= $(PREFIX)/sbin
SBINDIR ?= $(DESTDIR)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= $(PREFIX)/share/locale

.PHONY: all genhomedircon
all: fixfiles genhomedircon chcat

install: all
	-mkdir -p $(BINDIR)
	install -m 755 chcat $(BINDIR)
	install -m 755 fixfiles $(SBINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 fixfiles.8 $(MANDIR)/man8/
	install -m 644 chcat.8 $(MANDIR)/man8/

clean:
	rm -f genhomedircon

indent:

relabel:
