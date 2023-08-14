# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
MANDIR ?=  $(PREFIX)/share/man
MAN5SUBDIR ?= man5
MAN5DIR ?= $(MANDIR)/$(MAN5SUBDIR)
MAN8SUBDIR ?= man8
MAN8DIR ?= $(MANDIR)/$(MAN8SUBDIR)

all:

install: all
	mkdir -p $(DESTDIR)$(MAN5DIR)
	mkdir -p $(DESTDIR)$(MAN8DIR)
	install -m 644 man5/*.5 $(DESTDIR)$(MAN5DIR)
	install -m 644 man8/*.8 $(DESTDIR)$(MAN8DIR)
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang}/man5 ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/$(MAN5SUBDIR) ; \
			install -m 644 $${lang}/man5/*.5 $(DESTDIR)$(MANDIR)/$${lang}/$(MAN5SUBDIR) ; \
		fi ; \
		if [ -e $${lang}/man8 ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/$(MAN8SUBDIR) ; \
			install -m 644 $${lang}/man8/*.8 $(DESTDIR)$(MANDIR)/$${lang}/$(MAN8SUBDIR) ; \
		fi ; \
	done

clean:
	-rm -f *~ \#*
	-rm -f man5/*~ man5/\#*
	-rm -f man8/*~ man8/\#*
