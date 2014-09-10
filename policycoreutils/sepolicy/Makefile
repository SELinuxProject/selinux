PYTHON ?= python

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SYSCONFDIR ?= $(DESTDIR)/etc/sysconfig
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
BASHCOMPLETIONDIR ?= $(DESTDIR)/usr/share/bash-completion/completions
SHAREDIR ?= $(PREFIX)/share/sandbox
override CFLAGS = -I$(PREFIX)/include -DPACKAGE="policycoreutils" -Wall -Werror -Wextra -W  -DSHARED -shared

BASHCOMPLETIONS=sepolicy-bash-completion.sh

all: python-build

python-build: info.c search.c common.h policy.h policy.c
	$(PYTHON) setup.py build

clean:
	$(PYTHON) setup.py clean
	-rm -rf build *~ \#* *pyc .#*

sepolgen:
	ln -sf sepolicy sepolgen

test:
	@$(PYTHON) test_sepolicy.py -v

install:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`
	[ -d $(BINDIR) ] || mkdir -p $(BINDIR)
	install -m 755 sepolicy.py $(BINDIR)/sepolicy
	(cd $(BINDIR); ln -sf sepolicy sepolgen)
	-mkdir -p $(MANDIR)/man8
	install -m 644 *.8 $(MANDIR)/man8
	-mkdir -p $(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(BASHCOMPLETIONDIR)/sepolicy
	-mkdir -p $(DESTDIR)/etc/dbus-1/system.d/
	install -m 644 org.selinux.conf $(DESTDIR)/etc/dbus-1/system.d/
	-mkdir -p $(DESTDIR)/usr/share/dbus-1/system-services
	install -m 644 org.selinux.service $(DESTDIR)/usr/share/dbus-1/system-services
	-mkdir -p $(DESTDIR)/usr/share/polkit-1/actions/
	install -m 644 org.selinux.policy $(DESTDIR)/usr/share/polkit-1/actions/
	-mkdir -p $(DESTDIR)/usr/share/system-config-selinux
	install -m 755 selinux_server.py $(DESTDIR)/usr/share/system-config-selinux
	install -m 644 *.desktop $(DATADIR)/system-config-selinux
	-mkdir -p $(DESTDIR) $(DATADIR)/pixmaps
	install -m 644 sepolicy_256.png $(DATADIR)/pixmaps/sepolicy.png
	for i in 16 22 32 48 256; do \
		mkdir -p $(DESTDIR) $(DATADIR)/icons/hicolor/$${i}x$${i}/apps; \
		install -m 644 sepolicy_$${i}.png $(DATADIR)/icons/hicolor/$${i}x$${i}/apps/sepolicy.png; \
	done

relabel:
