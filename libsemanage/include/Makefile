# Installation directories.
PREFIX ?= /usr
INCDIR ?= $(PREFIX)/include/semanage

all:

install: all
	test -d $(DESTDIR)$(INCDIR) || install -m 755 -d $(DESTDIR)$(INCDIR)
	install -m 644 $(wildcard semanage/*.h) $(DESTDIR)$(INCDIR)
