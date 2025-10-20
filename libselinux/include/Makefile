# Installation directories.
PREFIX ?= /usr
INCDIR = $(PREFIX)/include/selinux

all:

install: all
	test -d $(DESTDIR)$(INCDIR) || install -m 755 -d $(DESTDIR)$(INCDIR)
	install -m 644 $(wildcard selinux/*.h) $(DESTDIR)$(INCDIR)

relabel:

distclean clean:
	-rm -f selinux/*~
