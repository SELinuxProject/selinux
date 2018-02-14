PYTHON ?= python

# Installation directories.
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
PYTHONLIBDIR ?= $(shell $(PYTHON) -c "from distutils.sysconfig import *; print(get_python_lib(prefix='$(PREFIX)'))")
PACKAGEDIR ?= $(PYTHONLIBDIR)
BASHCOMPLETIONDIR ?= $(PREFIX)/share/bash-completion/completions

TARGETS=semanage

BASHCOMPLETIONS=semanage-bash-completion.sh 

all: $(TARGETS)

install: all
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 semanage $(DESTDIR)$(SBINDIR)
	install -m 644 *.8 $(DESTDIR)$(MANDIR)/man8
	test -d $(DESTDIR)/$(PACKAGEDIR) || install -m 755 -d $(DESTDIR)/$(PACKAGEDIR)
	install -m 755 seobject.py $(DESTDIR)/$(PACKAGEDIR)
	-mkdir -p $(DESTDIR)$(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(DESTDIR)$(BASHCOMPLETIONDIR)/semanage

test:
	@$(PYTHON) test-semanage.py -a
clean:

indent:

relabel:
