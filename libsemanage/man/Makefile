# Installation directories.
MAN3DIR ?= $(DESTDIR)/usr/share/man/man3

all:

install: all
	mkdir -p $(MAN3DIR)
	install -m 644 man3/*.3 $(MAN3DIR)

