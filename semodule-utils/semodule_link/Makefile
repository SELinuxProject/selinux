# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol

all: semodule_link

semodule_link:  semodule_link.o 

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 semodule_link $(DESTDIR)$(BINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 semodule_link.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

relabel:

clean:
	-rm -f semodule_link *.o
