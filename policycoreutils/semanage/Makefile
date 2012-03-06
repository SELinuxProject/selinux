# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
PYLIBVER ?= $(shell python -c 'import sys;print "python%d.%d" % sys.version_info[0:2]')
PYTHONLIBDIR ?= $(LIBDIR)/$(PYLIBVER)
BASHCOMPLETIONDIR ?= $(DESTDIR)/etc/bash_completion.d/

TARGETS=semanage

BASHCOMPLETIONS=semanage-bash-completion.sh 

all: $(TARGETS)

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 semanage $(SBINDIR)
	install -m 644 semanage.8 $(MANDIR)/man8
	test -d $(PYTHONLIBDIR)/site-packages || install -m 755 -d $(PYTHONLIBDIR)/site-packages
	install -m 755 seobject.py $(PYTHONLIBDIR)/site-packages
	-mkdir -p $(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(BASHCOMPLETIONDIR)

clean:

indent:

relabel:
