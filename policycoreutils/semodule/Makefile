# Installation directories.
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol -lselinux -lsemanage
SEMODULE_OBJS = semodule.o

all: semodule genhomedircon

semodule: $(SEMODULE_OBJS)

genhomedircon:
	ln -sf semodule genhomedircon

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 semodule $(DESTDIR)$(SBINDIR)
	(cd $(DESTDIR)$(SBINDIR); ln -sf semodule genhomedircon)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 semodule.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 genhomedircon.8 $(DESTDIR)$(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule *.o genhomedircon

indent:
	../../scripts/Lindent $(wildcard *.[ch])

