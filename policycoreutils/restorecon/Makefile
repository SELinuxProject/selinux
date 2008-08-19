# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(DESTDIR)/sbin
MANDIR = $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include -D_FILE_OFFSET_BITS=64
LDLIBS += -lselinux -lsepol -L$(PREFIX)/lib

all: restorecon

restorecon:  restorecon.o 
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 restorecon $(SBINDIR)
	install -m 644 restorecon.8 $(MANDIR)/man8

clean:
	-rm -f restorecon *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(SBINDIR)/restorecon
