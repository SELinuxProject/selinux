# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = -lsepol -lselinux -lsemanage -L$(LIBDIR)
SETSEBOOL_OBJS = setsebool.o

all: setsebool

setsebool: $(SETSEBOOL_OBJS)

install: all
	-mkdir -p $(SBINDIR)
	install -m 755 setsebool $(SBINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 setsebool.8 $(MANDIR)/man8/

relabel:

clean:
	-rm -f setsebool *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

