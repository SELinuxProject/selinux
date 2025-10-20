# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
SBINDIR ?= /sbin
MANDIR = $(PREFIX)/share/man
AUDITH ?= $(shell test -f /usr/include/libaudit.h && echo y)

CFLAGS ?= -g -Werror -Wall -W
override CFLAGS += -I../../libselinux/include
override LDFLAGS+= -L../../libselinux/src
override LDLIBS += $(LIBSELINUX_LDLIBS) -lsepol -lpthread

ifeq ($(AUDITH), y)
	override CFLAGS += -DUSE_AUDIT
	override LDLIBS += -laudit
endif

all: setfiles restorecon restorecon_xattr

setfiles: setfiles.o restore.o

restorecon: setfiles
	ln -sf setfiles restorecon

restorecon_xattr: restorecon_xattr.o restore.o

install: all
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 setfiles $(DESTDIR)$(SBINDIR)
	(cd $(DESTDIR)$(SBINDIR) && ln -sf setfiles restorecon)
	install -m 755 restorecon_xattr $(DESTDIR)$(SBINDIR)
	install -m 644 setfiles.8 $(DESTDIR)$(MANDIR)/man8/setfiles.8
	install -m 644 restorecon.8 $(DESTDIR)$(MANDIR)/man8/restorecon.8
	install -m 644 restorecon_xattr.8 $(DESTDIR)$(MANDIR)/man8/restorecon_xattr.8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			[ -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

clean:
	rm -f setfiles restorecon restorecon_xattr *.o

relabel: install
	$(DESTDIR)$(SBINDIR)/restorecon $(DESTDIR)$(SBINDIR)/setfiles $(DESTDIR)$(SBINDIR)/restorecon_xattr
