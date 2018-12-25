
# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= /etc
LOCALEDIR ?= $(DESTDIR)$(PREFIX)/share/locale
PAMH ?= $(shell test -f /usr/include/security/pam_appl.h && echo y)
AUDITH ?= $(shell test -f /usr/include/libaudit.h && echo y)

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
override LDLIBS += -lselinux
ifeq ($(PAMH), y)
	override CFLAGS += -DUSE_PAM
	override LDLIBS += -lpam -lpam_misc
else
	override CFLAGS += -D_XOPEN_SOURCE=500
	override LDLIBS += -lcrypt
endif
ifeq ($(AUDITH), y)
	override CFLAGS += -DUSE_AUDIT
	override LDLIBS += -laudit
endif

TARGETS=$(patsubst %.c,%,$(sort $(wildcard *.c)))

all: $(TARGETS)

open_init_pty: open_init_pty.c
	$(LINK.c) $^ -ldl -lutil -o $@


install: all
	test -d $(DESTDIR)$(SBINDIR)      || install -m 755 -d $(DESTDIR)$(SBINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 755 run_init $(DESTDIR)$(SBINDIR)
	install -m 755 open_init_pty $(DESTDIR)$(SBINDIR)
	install -m 644 run_init.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 open_init_pty.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
ifeq ($(PAMH), y)
	install -m 644 run_init.pamd $(DESTDIR)$(ETCDIR)/pam.d/run_init
endif

clean:
	-rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(DESTDIR)$(SBINDIR)/run_init $(DESTDIR)$(SBINDIR)/open_init_pty
