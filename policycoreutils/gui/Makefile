# Installation directories.
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/system-config-selinux

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

all: $(TARGETS) system-config-selinux.py polgengui.py templates polgen.py

install: all
	-mkdir -p $(SHAREDIR)/templates
	-mkdir -p $(BINDIR)
	install -m 755 system-config-selinux.py $(SHAREDIR)
	install -m 755 polgengui.py $(SHAREDIR)
	install -m 755 polgen.py $(SHAREDIR)
	(cd $(BINDIR); 	ln -fs ../share/system-config-selinux/polgen.py sepolgen)
	install -m 644 $(TARGETS) $(SHAREDIR)
	install -m 644 templates/*.py $(SHAREDIR)/templates/

clean:

indent:

relabel:
