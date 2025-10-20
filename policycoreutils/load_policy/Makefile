# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= $(DESTDIR)$(PREFIX)/share/locale

CFLAGS ?= -Werror -Wall -W
override CFLAGS += $(LDFLAGS) -I../../libselinux/include -L../../libselinux/src -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
override LDLIBS += $(LIBSELINUX_LDLIBS) -lsepol

TARGETS=$(patsubst %.c,%,$(sort $(wildcard *.c)))

all: $(TARGETS)

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 $(TARGETS) $(DESTDIR)$(SBINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 load_policy.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done

clean:
	-rm -f $(TARGETS) *.o 

relabel:
	/sbin/restorecon $(DESTDIR)$(SBINDIR)/load_policy 
