PYTHON ?= python3

# Installation directories.
LINGUAS ?= ru
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
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			[ -d $(DESTDIR)$(MANDIR)/$${lang}/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	test -d $(DESTDIR)/$(PACKAGEDIR) || install -m 755 -d $(DESTDIR)/$(PACKAGEDIR)
	install -m 644 seobject.py $(DESTDIR)/$(PACKAGEDIR)
	-mkdir -p $(DESTDIR)$(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(DESTDIR)$(BASHCOMPLETIONDIR)/semanage

test:
	@$(PYTHON) test-semanage.py -a
clean:

indent:

relabel:
