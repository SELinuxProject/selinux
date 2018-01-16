# Installation directories.
PREFIX ?= /usr
MAN3DIR ?= $(DESTDIR)$(PREFIX)/share/man/man3
MAN5DIR ?= $(DESTDIR)$(PREFIX)/share/man/man5

all:

install: all
	mkdir -p $(MAN3DIR)
	mkdir -p $(MAN5DIR)
	install -m 644 man3/*.3 $(MAN3DIR)
	install -m 644 man5/*.5 $(MAN5DIR)

