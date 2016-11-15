# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = -lsepol -L$(LIBDIR)

all: semodule_link

semodule_link:  semodule_link.o 

install: all
	-mkdir -p $(BINDIR)
	install -m 755 semodule_link $(BINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 644 semodule_link.8 $(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule_link *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

