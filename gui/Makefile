# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/system-config-selinux
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(PREFIX)/share/man
DESKTOPDIR ?= $(PREFIX)/share/applications

TARGETS= \
booleansPage.py \
domainsPage.py \
fcontextPage.py \
loginsPage.py \
modulesPage.py \
polgen.ui \
portsPage.py \
semanagePage.py \
statusPage.py \
system-config-selinux.png \
system-config-selinux.ui \
usersPage.py

all: $(TARGETS) system-config-selinux.py polgengui.py

install: all
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SHAREDIR)
	-mkdir -p $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(DATADIR)/pixmaps
	-mkdir -p $(DESTDIR)$(DATADIR)/icons/hicolor/24x24/apps
	-mkdir -p $(DESTDIR)$(DATADIR)/polkit-1/actions/
	-mkdir -p $(DESTDIR)$(DESKTOPDIR)
	install -m 755 system-config-selinux.py $(DESTDIR)$(SHAREDIR)
	install -m 755 system-config-selinux $(DESTDIR)$(BINDIR)
	install -m 755 polgengui.py $(DESTDIR)$(BINDIR)/selinux-polgengui
	install -m 644 $(TARGETS) $(DESTDIR)$(SHAREDIR)
	install -m 644 system-config-selinux.8 $(DESTDIR)$(MANDIR)/man8
	install -m 644 selinux-polgengui.8 $(DESTDIR)$(MANDIR)/man8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	install -m 644 system-config-selinux.png $(DESTDIR)$(DATADIR)/pixmaps
	install -m 644 system-config-selinux.png $(DESTDIR)$(DATADIR)/icons/hicolor/24x24/apps
	install -m 644 system-config-selinux.png $(DESTDIR)$(DATADIR)/system-config-selinux
	install -m 644 *.desktop $(DESTDIR)$(DESKTOPDIR)
	-mkdir -p $(DESTDIR)$(DATADIR)/pixmaps
	install -m 644 sepolicy_256.png $(DESTDIR)$(DATADIR)/pixmaps/sepolicy.png
	for i in 16 22 32 48 256; do \
		mkdir -p $(DESTDIR)$(DATADIR)/icons/hicolor/$${i}x$${i}/apps; \
		install -m 644 sepolicy_$${i}.png $(DESTDIR)$(DATADIR)/icons/hicolor/$${i}x$${i}/apps/sepolicy.png; \
	done
	install -m 644 org.selinux.config.policy $(DESTDIR)$(DATADIR)/polkit-1/actions/
clean:

indent:

relabel:

test:
