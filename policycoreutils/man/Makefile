# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
MANDIR ?= $(PREFIX)/share/man
MAN5DIR ?= $(MANDIR)/man5

all:

clean:

install: all
	mkdir -p $(DESTDIR)$(MAN5DIR)
	install -m 644 man5/*.5 $(DESTDIR)$(MAN5DIR)
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang}/man5 ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man5 ; \
			install -m 644 $${lang}/man5/*.5 $(DESTDIR)$(MANDIR)/$${lang}/man5 ; \
		fi ; \
	done

relabel:
