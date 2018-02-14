# Installation directories.
PREFIX ?= /usr
MAN3DIR ?= $(PREFIX)/share/man/man3
MAN5DIR ?= $(PREFIX)/share/man/man5

all:

install: all
	mkdir -p $(DESTDIR)$(MAN3DIR)
	mkdir -p $(DESTDIR)$(MAN5DIR)
	install -m 644 man3/*.3 $(DESTDIR)$(MAN3DIR)
	install -m 644 man5/*.5 $(DESTDIR)$(MAN5DIR)

