# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(DESTDIR)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib
AUDITH = $(shell ls /usr/include/libaudit.h 2>/dev/null)

CFLAGS = -g -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include
LDLIBS = -lselinux -lsepol -L$(LIBDIR)

ifeq (${AUDITH}, /usr/include/libaudit.h)
	override CFLAGS += -DUSE_AUDIT
	LDLIBS += -laudit
endif

all: setfiles restorecon

setfiles:  setfiles.o restore.o

restorecon: setfiles
	ln -sf setfiles restorecon

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 setfiles $(SBINDIR)
	(cd $(SBINDIR) && ln -sf setfiles restorecon)
	install -m 644 setfiles.8 restorecon.8 $(MANDIR)/man8

clean:
	rm -f setfiles restorecon *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(SBINDIR)/setfiles
