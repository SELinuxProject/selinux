# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCDIR ?= $(PREFIX)/include/sepol

all:

install: all
	test -d $(INCDIR) || install -m 755 -d $(INCDIR)
	test -d $(INCDIR)/policydb || install -m 755 -d $(INCDIR)/policydb
	install -m 644 $(wildcard sepol/*.h) $(INCDIR)
	install -m 644 $(wildcard sepol/policydb/*.h) $(INCDIR)/policydb

indent:
	../../scripts/Lindent $(wildcard sepol/*.h)
