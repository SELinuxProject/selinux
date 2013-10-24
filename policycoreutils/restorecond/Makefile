# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SBINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
MANDIR = $(PREFIX)/share/man
AUTOSTARTDIR = $(DESTDIR)/etc/xdg/autostart
DBUSSERVICEDIR = $(DESTDIR)/usr/share/dbus-1/services
SYSTEMDDIR ?= $(DESTDIR)/usr/lib/systemd

autostart_DATA = sealertauto.desktop
INITDIR ?= $(DESTDIR)/etc/rc.d/init.d
SELINUXDIR = $(DESTDIR)/etc/selinux

DBUSFLAGS = -DHAVE_DBUS -I/usr/include/dbus-1.0 -I/usr/lib64/dbus-1.0/include -I/usr/lib/dbus-1.0/include
DBUSLIB = -ldbus-glib-1 -ldbus-1

CFLAGS ?= -g -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include $(DBUSFLAGS) -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I/usr/lib/glib-2.0/include

LDLIBS += -lselinux $(DBUSLIB) -lglib-2.0 -L$(LIBDIR)

all: restorecond

restorecond.o utmpwatcher.o stringslist.o user.o watch.o: restorecond.h

restorecond:  ../setfiles/restore.o restorecond.o utmpwatcher.o stringslist.o user.o watch.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 restorecond $(SBINDIR)
	install -m 644 restorecond.8 $(MANDIR)/man8
	-mkdir -p $(INITDIR)
	install -m 755 restorecond.init $(INITDIR)/restorecond
	-mkdir -p $(SELINUXDIR)
	install -m 644 restorecond.conf $(SELINUXDIR)/restorecond.conf
	install -m 644 restorecond_user.conf $(SELINUXDIR)/restorecond_user.conf
	-mkdir -p $(AUTOSTARTDIR)
	install -m 644 restorecond.desktop $(AUTOSTARTDIR)/restorecond.desktop
	-mkdir -p $(DBUSSERVICEDIR)
	install -m 600 org.selinux.Restorecond.service  $(DBUSSERVICEDIR)/org.selinux.Restorecond.service
	-mkdir -p $(SYSTEMDDIR)/system
	install -m 644 restorecond.service $(SYSTEMDDIR)/system/
relabel: install
	/sbin/restorecon $(SBINDIR)/restorecond 

clean:
	-rm -f restorecond *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

