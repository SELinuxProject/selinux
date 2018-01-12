# Installation directories.
PREFIX ?= /usr
MAN8DIR ?= $(DESTDIR)$(PREFIX)/share/man/man8
MAN3DIR ?= $(DESTDIR)$(PREFIX)/share/man/man3

all:

install: all
	mkdir -p $(MAN3DIR)
	mkdir -p $(MAN8DIR)
	install -m 644 man3/*.3 $(MAN3DIR)
	install -m 644 man8/*.8 $(MAN8DIR)

