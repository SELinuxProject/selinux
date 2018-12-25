# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
MANDIR ?=  $(PREFIX)/share/man
MAN8SUBDIR ?= man8
MAN8DIR ?= $(MANDIR)/$(MAN8SUBDIR)

all:

install: all
	mkdir -p $(DESTDIR)$(MAN8DIR)
	install -m 644 man8/*.8 $(DESTDIR)$(MAN8DIR)
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang}/man8 ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/$(MAN8SUBDIR) ; \
			install -m 644 $${lang}/man8/*.8 $(DESTDIR)$(MANDIR)/$${lang}/$(MAN8SUBDIR) ; \
		fi ; \
	done

clean:
	-rm -f *~ \#*
	-rm -f man8/*~ man8/\#*
