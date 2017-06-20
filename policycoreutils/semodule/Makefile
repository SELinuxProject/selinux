# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol -lselinux -lsemanage
SEMODULE_OBJS = semodule.o

all: semodule genhomedircon

semodule: $(SEMODULE_OBJS)

genhomedircon:
	ln -sf semodule genhomedircon

install: all
	-mkdir -p $(SBINDIR)
	install -m 755 semodule $(SBINDIR)
	(cd $(SBINDIR); ln -sf semodule genhomedircon)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 644 semodule.8 $(MANDIR)/man8/
	install -m 644 genhomedircon.8 $(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule *.o genhomedircon

indent:
	../../scripts/Lindent $(wildcard *.[ch])

