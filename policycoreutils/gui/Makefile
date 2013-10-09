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
usersPage.py

all: $(TARGETS) system-config-selinux.py polgengui.py

install: all
	-mkdir -p $(SHAREDIR)
	-mkdir -p $(BINDIR)
	install -m 755 system-config-selinux.py $(SHAREDIR)
	install -m 755 polgengui.py $(SHAREDIR)
	install -m 755 sepolgen $(BINDIR)
	install -m 644 $(TARGETS) $(SHAREDIR)

clean:

indent:

relabel:
