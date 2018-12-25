# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
SBINDIR ?= /sbin
MANDIR = $(PREFIX)/share/man
AUDITH ?= $(shell test -f /usr/include/libaudit.h && echo y)

ABORT_ON_ERRORS=$(shell grep "^\#define ABORT_ON_ERRORS" setfiles.c | awk -S '{ print $$3 }')

CFLAGS ?= -g -Werror -Wall -W
override LDLIBS += -lselinux -lsepol

ifeq ($(AUDITH), y)
	override CFLAGS += -DUSE_AUDIT
	override LDLIBS += -laudit
endif

all: setfiles restorecon restorecon_xattr man

setfiles: setfiles.o restore.o

restorecon: setfiles
	ln -sf setfiles restorecon

restorecon_xattr: restorecon_xattr.o restore.o

man:
	@cp -af setfiles.8 setfiles.8.man
	@sed -i "s/ABORT_ON_ERRORS/$(ABORT_ON_ERRORS)/g" setfiles.8.man

install: all
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 setfiles $(DESTDIR)$(SBINDIR)
	(cd $(DESTDIR)$(SBINDIR) && ln -sf setfiles restorecon)
	install -m 755 restorecon_xattr $(DESTDIR)$(SBINDIR)
	install -m 644 setfiles.8.man $(DESTDIR)$(MANDIR)/man8/setfiles.8
	install -m 644 restorecon.8 $(DESTDIR)$(MANDIR)/man8/restorecon.8
	install -m 644 restorecon_xattr.8 $(DESTDIR)$(MANDIR)/man8/restorecon_xattr.8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			[ -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

clean:
	rm -f setfiles restorecon restorecon_xattr *.o setfiles.8.man

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	$(DESTDIR)$(SBINDIR)/restorecon $(DESTDIR)$(SBINDIR)/setfiles $(DESTDIR)$(SBINDIR)/restorecon_xattr
