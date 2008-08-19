# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(DESTDIR)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

AUDITH = $(shell ls /usr/include/libaudit.h 2>/dev/null)

CFLAGS = -Werror -Wall -W
override CFLAGS += -D_FILE_OFFSET_BITS=64 -I$(PREFIX)/include
LDLIBS = -lselinux -lsepol -L$(LIBDIR)

ifeq (${AUDITH}, /usr/include/libaudit.h)
	override CFLAGS += -DUSE_AUDIT
	LDLIBS += -laudit
endif

all: setfiles

setfiles:  setfiles.o 

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 setfiles $(SBINDIR)
	install -m 644 setfiles.8 $(MANDIR)/man8

clean:
	rm -f setfiles *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(SBINDIR)/setfiles
