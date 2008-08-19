# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCDIR ?= $(PREFIX)/include/selinux

install:
	test -d $(INCDIR) || install -m 755 -d $(INCDIR)
	install -m 644 $(wildcard selinux/*.h) $(INCDIR)

indent:
	../../scripts/Lindent $(wildcard selinux/*.h)

