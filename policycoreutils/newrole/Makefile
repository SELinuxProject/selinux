# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LOCALEDIR = /usr/share/locale
PAMH ?= $(shell test -f /usr/include/security/pam_appl.h && echo y)
AUDITH ?= $(shell test -f /usr/include/libaudit.h && echo y)
# Enable capabilities to permit newrole to generate audit records.
# This will make newrole a setuid root program.
# The capabilities used are: CAP_AUDIT_WRITE.
AUDIT_LOG_PRIV ?= n
# Enable capabilities to permit newrole to utilitize the pam_namespace module.
# This will make newrole a setuid root program.
# The capabilities used are: CAP_SYS_ADMIN, CAP_CHOWN, CAP_FOWNER and
# CAP_DAC_OVERRIDE. 
NAMESPACE_PRIV ?= n
# If LSPP_PRIV is y, then newrole will be made into setuid root program.
# Enabling this option will force AUDIT_LOG_PRIV and NAMESPACE_PRIV to be y.
LSPP_PRIV ?= n
VERSION = $(shell cat ../VERSION)

CFLAGS ?= -Werror -Wall -W
EXTRA_OBJS =
override CFLAGS += -DVERSION=\"$(VERSION)\" -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
override LDLIBS += -lselinux
ifeq ($(PAMH), y)
	override CFLAGS += -DUSE_PAM
	EXTRA_OBJS += hashtab.o
	override LDLIBS += -lpam -lpam_misc
else
	override CFLAGS += -D_XOPEN_SOURCE=500
	override LDLIBS += -lcrypt
endif
ifeq ($(AUDITH), y)
	override CFLAGS += -DUSE_AUDIT
	override LDLIBS += -laudit
endif
ifeq ($(LSPP_PRIV),y)
	override AUDIT_LOG_PRIV=y
	override NAMESPACE_PRIV=y
endif
ifeq ($(AUDIT_LOG_PRIV),y)
	override CFLAGS += -DAUDIT_LOG_PRIV
	IS_SUID=y
endif
ifeq ($(NAMESPACE_PRIV),y)
	override CFLAGS += -DNAMESPACE_PRIV
	IS_SUID=y
endif
ifeq ($(IS_SUID),y)
	MODE := 4555
	override LDLIBS += -lcap-ng
else
	MODE := 0555
endif

all: newrole

newrole: newrole.o $(EXTRA_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	test -d $(BINDIR)      || install -m 755 -d $(BINDIR)
	test -d $(ETCDIR)/pam.d || install -m 755 -d $(ETCDIR)/pam.d
	test -d $(MANDIR)/man1 || install -m 755 -d $(MANDIR)/man1
	install -m $(MODE) newrole $(BINDIR)
	install -m 644 newrole.1 $(MANDIR)/man1/
ifeq ($(PAMH), y)
	test -d $(ETCDIR)/pam.d || install -m 755 -d $(ETCDIR)/pam.d
ifeq ($(LSPP_PRIV),y)
	install -m 644 newrole-lspp.pamd $(ETCDIR)/pam.d/newrole
else
	install -m 644 newrole.pamd $(ETCDIR)/pam.d/newrole
endif
endif

clean:
	rm -f newrole *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: install
	/sbin/restorecon $(BINDIR)/newrole
