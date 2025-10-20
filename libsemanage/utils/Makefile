# Installation directories.
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
SELINUXEXECDIR ?= $(LIBEXECDIR)/selinux/

all:

install: all
	-mkdir -p $(DESTDIR)$(SELINUXEXECDIR)
	install -m 755 semanage_migrate_store $(DESTDIR)$(SELINUXEXECDIR)

clean:

distclean: clean

relabel:
