# Installation directories.
PREFIX ?= /usr
MAN8DIR ?= $(PREFIX)/share/man/man8
MAN3DIR ?= $(PREFIX)/share/man/man3

all:

install: all
	mkdir -p $(DESTDIR)$(MAN3DIR)
	mkdir -p $(DESTDIR)$(MAN8DIR)
	install -m 644 man3/*.3 $(DESTDIR)$(MAN3DIR)
	install -m 644 man8/*.8 $(DESTDIR)$(MAN8DIR)

