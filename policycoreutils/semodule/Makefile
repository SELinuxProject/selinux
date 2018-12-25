# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol -lselinux -lsemanage
SEMODULE_OBJS = semodule.o

all: semodule genhomedircon

semodule: $(SEMODULE_OBJS)

genhomedircon:
	ln -sf semodule genhomedircon

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 semodule $(DESTDIR)$(SBINDIR)
	(cd $(DESTDIR)$(SBINDIR); ln -sf semodule genhomedircon)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 semodule.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 genhomedircon.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

relabel:

clean:
	-rm -f semodule *.o genhomedircon

indent:
	../../scripts/Lindent $(wildcard *.[ch])

