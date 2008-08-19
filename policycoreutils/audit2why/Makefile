# Installation directories.
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= ${PREFIX}/lib
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
INCLUDEDIR ?= ${PREFIX}/include


CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = ${LIBDIR}/libsepol.a -lselinux -lsepol -L$(LIBDIR)

TARGETS=audit2why

all: $(TARGETS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 audit2why.8 $(MANDIR)/man8/

clean:
	-rm -f $(TARGETS) *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
