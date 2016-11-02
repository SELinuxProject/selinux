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
CFLAGS ?= -Wall -Werror -Wextra -W
override CFLAGS += -I$(PREFIX)/include -DPACKAGE="policycoreutils" -DSHARED -shared

BASHCOMPLETIONS=sepolicy-bash-completion.sh

all: python-build

python-build:
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

relabel:
