# secon tool - command-line context
LINGUAS ?= ru
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

WARNS=-Werror -W -Wall -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -Wfloat-equal
VERSION = $(shell cat ../VERSION)
CFLAGS ?= $(WARNS) -O1
override CFLAGS += -DVERSION=\"$(VERSION)\"
override LDLIBS += -lselinux

all: secon

secon: secon.o 

install-nogui: install

install: all
	install -m 755 secon $(DESTDIR)$(BINDIR);

	test -d $(DESTDIR)$(MANDIR)/man1 || install -m 755 -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 secon.1 $(DESTDIR)$(MANDIR)/man1
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man1 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man1 ; \
			install -m 644 $${lang}/*.1 $(DESTDIR)$(MANDIR)/$${lang}/man1/ ; \
		fi ; \
	done

relabel:
	/sbin/restorecon $(DESTDIR)$(BINDIR)/secon

clean:
	rm -f *.o core* secon *~ *.bak

indent:
	../../scripts/Lindent $(wildcard *.[ch])

bare: clean

.PHONY: clean bare
