# Installation directories.
PREFIX ?= /usr
MAN8DIR ?= $(PREFIX)/share/man/man8

all:

install: all
	mkdir -p $(DESTDIR)$(MAN8DIR)
	install -m 644 man8/*.8 $(DESTDIR)$(MAN8DIR)

clean:
	-rm -f *~ \#*
	-rm -f man8/*~ man8/\#*
