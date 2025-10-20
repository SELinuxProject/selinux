# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= /etc
LOCALEDIR = $(DESTDIR)$(PREFIX)/share/locale
INCLUDEDIR ?= $(PREFIX)/include
PAMH ?= $(shell test -f $(INCLUDEDIR)/security/pam_appl.h && echo y)
AUDITH ?= $(shell test -f $(INCLUDEDIR)/libaudit.h && echo y)
# Enable capabilities to permit newrole to generate audit records.
# This will make newrole a setuid root program.
# The capabilities used are: CAP_AUDIT_WRITE.
AUDIT_LOG_PRIV ?= n
# Enable capabilities to permit newrole to utilize the pam_namespace module.
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
override CFLAGS += -I../../libselinux/include -DVERSION=\"$(VERSION)\" -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
override LDFLAGS+= -L../../libselinux/src
override LDLIBS += $(LIBSELINUX_LDLIBS)
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
	test -d $(DESTDIR)$(BINDIR)      || install -m 755 -d $(DESTDIR)$(BINDIR)
	test -d $(DESTDIR)$(ETCDIR)/pam.d || install -m 755 -d $(DESTDIR)$(ETCDIR)/pam.d
	test -d $(DESTDIR)$(MANDIR)/man1 || install -m 755 -d $(DESTDIR)$(MANDIR)/man1
	install -m $(MODE) newrole $(DESTDIR)$(BINDIR)
	install -m 644 newrole.1 $(DESTDIR)$(MANDIR)/man1/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			test -d $(DESTDIR)$(MANDIR)/$${lang}/man1 || install -m 755 -d $(DESTDIR)$(MANDIR)/$${lang}/man1 ; \
			install -m 644 $${lang}/*.1 $(DESTDIR)$(MANDIR)/$${lang}/man1/ ; \
		fi ; \
	done
ifeq ($(PAMH), y)
	test -d $(DESTDIR)$(ETCDIR)/pam.d || install -m 755 -d $(DESTDIR)$(ETCDIR)/pam.d
ifeq ($(LSPP_PRIV),y)
	install -m 644 newrole-lspp.pamd $(DESTDIR)$(ETCDIR)/pam.d/newrole
else
	install -m 644 newrole.pamd $(DESTDIR)$(ETCDIR)/pam.d/newrole
endif
endif

clean:
	rm -f newrole *.o 

relabel: install
	/sbin/restorecon $(DESTDIR)$(BINDIR)/newrole

test-build-options:
	$(MAKE) PAMH=y AUDITH=y AUDIT_LOG_PRIV=y NAMESPACE_PRIV=y clean newrole
	$(MAKE) PAMH=y AUDITH=y AUDIT_LOG_PRIV=y NAMESPACE_PRIV=n clean newrole
	$(MAKE) PAMH=y AUDITH=y AUDIT_LOG_PRIV=n NAMESPACE_PRIV=y clean newrole
	$(MAKE) PAMH=y AUDITH=y AUDIT_LOG_PRIV=n NAMESPACE_PRIV=n clean newrole
	$(MAKE) PAMH=y AUDITH=y AUDIT_LOG_PRIV=y NAMESPACE_PRIV=y clean newrole
	$(MAKE) PAMH=y AUDITH=n AUDIT_LOG_PRIV=n NAMESPACE_PRIV=y clean newrole
	$(MAKE) PAMH=y AUDITH=n AUDIT_LOG_PRIV=n NAMESPACE_PRIV=n clean newrole
	$(MAKE) PAMH=n AUDITH=y AUDIT_LOG_PRIV=y NAMESPACE_PRIV=n clean newrole
	$(MAKE) PAMH=n AUDITH=y AUDIT_LOG_PRIV=n NAMESPACE_PRIV=n clean newrole
	$(MAKE) PAMH=n AUDITH=n AUDIT_LOG_PRIV=n NAMESPACE_PRIV=n clean newrole
	$(MAKE) clean
