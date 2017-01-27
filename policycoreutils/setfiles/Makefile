# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SBINDIR ?= $(DESTDIR)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib
AUDITH = $(shell ls /usr/include/libaudit.h 2>/dev/null)

ABORT_ON_ERRORS=$(shell grep "^\#define ABORT_ON_ERRORS" setfiles.c | awk -S '{ print $$3 }')

CFLAGS ?= -g -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include
LDLIBS = -lselinux -lsepol -L$(LIBDIR)

ifeq ($(AUDITH), /usr/include/libaudit.h)
	override CFLAGS += -DUSE_AUDIT
	LDLIBS += -laudit
endif

all: setfiles restorecon restorecon_xattr man

setfiles:  setfiles.o restore.o

restorecon: setfiles
	ln -sf setfiles restorecon

restorecon_xattr:  restorecon_xattr.o restore.o

man:
	@cp -af setfiles.8 setfiles.8.man
	@sed -i "s/ABORT_ON_ERRORS/$(ABORT_ON_ERRORS)/g" setfiles.8.man

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 setfiles $(SBINDIR)
	(cd $(SBINDIR) && ln -sf setfiles restorecon)
	install -m 755 restorecon_xattr $(SBINDIR)
	install -m 644 setfiles.8.man $(MANDIR)/man8/setfiles.8
	install -m 644 restorecon.8 $(MANDIR)/man8/restorecon.8
	install -m 644 restorecon_xattr.8 $(MANDIR)/man8/restorecon_xattr.8

clean:
	rm -f setfiles restorecon restorecon_xattr *.o setfiles.8.man

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	$(SBINDIR)/restorecon $(SBINDIR)/setfiles $(SBINDIR)/restorecon_xattr
