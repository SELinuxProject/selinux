# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCDIR ?= $(PREFIX)/include/selinux

all:

install: all
	test -d $(INCDIR) || install -m 755 -d $(INCDIR)
	install -m 644 $(wildcard selinux/*.h) $(INCDIR)

relabel:

indent:
	../../scripts/Lindent $(wildcard selinux/*.h)

distclean clean:
	-rm -f selinux/*~

