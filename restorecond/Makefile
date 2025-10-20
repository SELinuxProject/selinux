PKG_CONFIG ?= pkg-config

# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
AUTOSTARTDIR = /etc/xdg/autostart
DBUSSERVICEDIR = $(PREFIX)/share/dbus-1/services
SYSTEMDSYSTEMUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd)
SYSTEMDUSERUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemduserunitdir systemd)

autostart_DATA = sealertauto.desktop
INITDIR ?= /etc/rc.d/init.d
SELINUXDIR = /etc/selinux

GIO_CFLAGS = -DHAVE_DBUS $(shell $(PKG_CONFIG) --cflags gio-2.0)
GIO_LIBS = $(shell $(PKG_CONFIG) --libs gio-2.0)

CFLAGS ?= -g -Werror -Wall -W
override CFLAGS += -I../../libselinux/include $(GIO_CFLAGS)
override LDFLAGS+= -L../../libselinux/src
override LDLIBS += -lselinux $(GIO_LIBS)

all: restorecond

restorecond.o utmpwatcher.o stringslist.o user.o watch.o: restorecond.h

restorecond:  restore.o restorecond.o utmpwatcher.o stringslist.o user.o watch.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 restorecond $(DESTDIR)$(SBINDIR)
	install -m 644 restorecond.8 $(DESTDIR)$(MANDIR)/man8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			[ -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	-mkdir -p $(DESTDIR)$(INITDIR)
	install -m 755 restorecond.init $(DESTDIR)$(INITDIR)/restorecond
	-mkdir -p $(DESTDIR)$(SELINUXDIR)
	install -m 644 restorecond.conf $(DESTDIR)$(SELINUXDIR)/restorecond.conf
	install -m 644 restorecond_user.conf $(DESTDIR)$(SELINUXDIR)/restorecond_user.conf
	-mkdir -p $(DESTDIR)$(AUTOSTARTDIR)
	install -m 644 restorecond.desktop $(DESTDIR)$(AUTOSTARTDIR)/restorecond.desktop
	-mkdir -p $(DESTDIR)$(DBUSSERVICEDIR)
	install -m 644 org.selinux.Restorecond.service  $(DESTDIR)$(DBUSSERVICEDIR)/org.selinux.Restorecond.service
	-mkdir -p $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)
	install -m 644 restorecond.service $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)
	-mkdir -p $(DESTDIR)$(SYSTEMDUSERUNITDIR)
	install -m 644 restorecond_user.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)
relabel: install
	/sbin/restorecon $(DESTDIR)$(SBINDIR)/restorecond 

clean:
	-rm -f restorecond *.o *~

test:
