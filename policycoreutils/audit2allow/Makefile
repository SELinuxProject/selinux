# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale

all: ;

install: all
	-mkdir -p $(BINDIR)
	install -m 755 audit2allow $(BINDIR)
	install -m 755 sepolgen-ifgen $(BINDIR)
	-mkdir -p $(MANDIR)/man1
	install -m 644 audit2allow.1 $(MANDIR)/man1/

clean:
	rm -f *~

indent: ;

relabel: ;
