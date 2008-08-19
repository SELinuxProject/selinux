# Installation directories.
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
PYLIBVER ?= $(shell python -c 'import sys;print "python%d.%d" % sys.version_info[0:2]')
PYTHONLIBDIR ?= $(LIBDIR)/$(PYLIBVER)

TARGETS=audit2allow

all: $(TARGETS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)
	-mkdir -p $(MANDIR)/man1
	install -m 644 audit2allow.1 $(MANDIR)/man1/
	test -d $(PYTHONLIBDIR)/site-packages || install -m 755 -d $(PYTHONLIBDIR)/site-packages
	install -m 755 avc.py $(PYTHONLIBDIR)/site-packages

clean:

indent:

relabel:
