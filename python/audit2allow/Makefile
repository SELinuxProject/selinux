PYTHON ?= python

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
INCLUDEDIR ?= $(PREFIX)/include
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

CFLAGS ?= -Werror -Wall -W

all: audit2why sepolgen-ifgen-attr-helper

sepolgen-ifgen-attr-helper: sepolgen-ifgen-attr-helper.o $(LIBSEPOLA)

audit2why:
	ln -sf audit2allow audit2why

test: all
	@$(PYTHON) test_audit2allow.py -v

install: all
	-mkdir -p $(BINDIR)
	install -m 755 audit2allow $(BINDIR)
	(cd $(BINDIR); ln -sf audit2allow audit2why)
	install -m 755 sepolgen-ifgen-attr-helper $(BINDIR)
	install -m 755 sepolgen-ifgen $(BINDIR)
	-mkdir -p $(MANDIR)/man1
	install -m 644 audit2allow.1 $(MANDIR)/man1/
	install -m 644 audit2why.1 $(MANDIR)/man1/

clean:
	rm -f *~ *.o sepolgen-ifgen-attr-helper

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: ;
