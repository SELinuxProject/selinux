PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man

override CFLAGS += -D_GNU_SOURCE
override LDLIBS += $(LIBSELINUX_LDLIBS)


all: unsetfiles

unsetfiles: unsetfiles.o

install: all
	test -d $(DESTDIR)$(SBINDIR)     || install -m 755 -d $(DESTDIR)$(SBINDIR)
	test -d $(DESTDIR)$(MANDIR)/man1 || install -m 755 -d $(DESTDIR)$(MANDIR)/man1
	install -m 755 unsetfiles $(DESTDIR)$(SBINDIR)
	install -m 644 unsetfiles.1 $(DESTDIR)$(MANDIR)/man1/

clean:
	-rm -f unsetfiles *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(DESTDIR)$(SBINDIR)/unsetfiles
