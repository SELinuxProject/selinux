# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

.PHONY: all
all: chcat

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 chcat $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 644 chcat.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

clean:

relabel:

test:
