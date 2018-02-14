# Installation directories.
PREFIX ?= /usr
MAN5DIR ?= $(PREFIX)/share/man/man5

all:

clean:

install: all
	mkdir -p $(DESTDIR)$(MAN5DIR)
	install -m 644 man5/*.5 $(DESTDIR)$(MAN5DIR)

relabel:
