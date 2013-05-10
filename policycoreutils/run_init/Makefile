
# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LOCALEDIR ?= /usr/share/locale
PAMH = $(shell ls /usr/include/security/pam_appl.h 2>/dev/null)
AUDITH = $(shell ls /usr/include/libaudit.h 2>/dev/null)

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
LDLIBS += -lselinux -L$(PREFIX)/lib
ifeq ($(PAMH), /usr/include/security/pam_appl.h)
	override CFLAGS += -DUSE_PAM
	LDLIBS += -lpam -lpam_misc
else
	override CFLAGS += -D_XOPEN_SOURCE=500
	LDLIBS += -lcrypt
endif
ifeq ($(AUDITH), /usr/include/libaudit.h)
	override CFLAGS += -DUSE_AUDIT
	LDLIBS += -laudit
endif

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS)

open_init_pty: open_init_pty.c
	$(LINK.c) $^ -ldl -lutil -o $@


install: all
	test -d $(SBINDIR)      || install -m 755 -d $(SBINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 755 run_init $(SBINDIR)
	install -m 755 open_init_pty $(SBINDIR)
	install -m 644 run_init.8 $(MANDIR)/man8/
	install -m 644 open_init_pty.8 $(MANDIR)/man8/
ifeq ($(PAMH), /usr/include/security/pam_appl.h)
	install -m 644 run_init.pamd $(ETCDIR)/pam.d/run_init
endif

clean:
	-rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(SBINDIR)/run_init $(SBINDIR)/open_init_pty
