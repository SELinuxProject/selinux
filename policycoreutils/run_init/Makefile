
# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LOCALEDIR ?= /usr/share/locale
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
	test -d $(SBINDIR)      || install -m 755 -d $(SBINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 755 run_init $(SBINDIR)
	install -m 755 open_init_pty $(SBINDIR)
	install -m 644 run_init.8 $(MANDIR)/man8/
	install -m 644 open_init_pty.8 $(MANDIR)/man8/
ifeq ($(PAMH), y)
	install -m 644 run_init.pamd $(ETCDIR)/pam.d/run_init
endif

clean:
	-rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(SBINDIR)/run_init $(SBINDIR)/open_init_pty
