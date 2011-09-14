# Installation directories.
MAN8DIR ?= $(DESTDIR)/usr/share/man/man8

all:

install: all
	mkdir -p $(MAN8DIR)
	install -m 644 man8/*.8 $(MAN8DIR)

clean:
	-rm -f *~ \#*
	-rm -f man8/*~ man8/\#*
