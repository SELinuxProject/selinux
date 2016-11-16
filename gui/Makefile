# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SYSCONFDIR ?= ${DESTDIR}/etc
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/system-config-selinux
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(PREFIX)/share/man

TARGETS= \
booleansPage.py \
domainsPage.py \
fcontextPage.py \
html_util.py \
loginsPage.py \
mappingsPage.py \
modulesPage.py \
polgen.glade \
portsPage.py \
semanagePage.py \
statusPage.py \
system-config-selinux.glade \
system-config-selinux.png \
usersPage.py

all: $(TARGETS) system-config-selinux.py polgengui.py

install: all
	-mkdir -p $(MANDIR)/man8
	-mkdir -p $(SHAREDIR)
	-mkdir -p $(BINDIR)
	-mkdir -p $(DATADIR)/pixmaps
	-mkdir -p $(DATADIR)/icons/hicolor/24x24/apps
	-mkdir -p $(SYSCONFDIR)
	-mkdir -p $(DATADIR)/polkit-1/actions/
	install -m 755 system-config-selinux.py $(SHAREDIR)
	install -m 755 system-config-selinux $(BINDIR)
	install -m 755 polgengui.py $(SHAREDIR)
	install -m 644 $(TARGETS) $(SHAREDIR)
	install -m 644 system-config-selinux.8 $(MANDIR)/man8
	install -m 644 selinux-polgengui.8 $(MANDIR)/man8
	install -m 644 system-config-selinux.png $(DATADIR)/pixmaps
	install -m 644 system-config-selinux.png $(DATADIR)/icons/hicolor/24x24/apps
	install -m 644 system-config-selinux.png $(DATADIR)/system-config-selinux
	install -m 644 *.desktop $(DATADIR)/system-config-selinux
	-mkdir -p $(DESTDIR) $(DATADIR)/pixmaps
	install -m 644 sepolicy_256.png $(DATADIR)/pixmaps/sepolicy.png
	for i in 16 22 32 48 256; do \
		mkdir -p $(DESTDIR) $(DATADIR)/icons/hicolor/$${i}x$${i}/apps; \
		install -m 644 sepolicy_$${i}.png $(DATADIR)/icons/hicolor/$${i}x$${i}/apps/sepolicy.png; \
	done
	install -m 644 org.selinux.config.policy $(DATADIR)/polkit-1/actions/
clean:

indent:

relabel:

test:
