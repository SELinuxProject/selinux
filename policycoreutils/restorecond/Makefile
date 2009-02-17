# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
INITDIR = $(DESTDIR)/etc/rc.d/init.d
SELINUXDIR = $(DESTDIR)/etc/selinux

CFLAGS ?= -g -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include -D_FILE_OFFSET_BITS=64
LDLIBS += -lselinux -L$(PREFIX)/lib

all: restorecond

restorecond:  restorecond.o utmpwatcher.o stringslist.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 restorecond $(SBINDIR)
	install -m 644 restorecond.8 $(MANDIR)/man8
	-mkdir -p $(INITDIR)
	install -m 755 restorecond.init $(INITDIR)/restorecond
	-mkdir -p $(SELINUXDIR)
	install -m 600 restorecond.conf $(SELINUXDIR)/restorecond.conf

relabel: install
	/sbin/restorecon $(SBINDIR)/restorecond 

clean:
	-rm -f restorecond *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

