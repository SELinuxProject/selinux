# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SYSCONFDIR ?= $(DESTDIR)/etc/sysconfig
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
PYTHON ?= /usr/bin/python
BASHCOMPLETIONDIR ?= $(DESTDIR)/etc/bash_completion.d/
SHAREDIR ?= $(PREFIX)/share/sandbox
override CFLAGS = -I$(PREFIX)/include -DPACKAGE="policycoreutils" -Wall -Werror -Wextra -W  -DSHARED -shared

BASHCOMPLETIONS=sepolicy-bash-completion.sh 

all: python-build

python-build: info.c search.c common.h policy.h policy.c
	$(PYTHON) setup.py build

clean:
	$(PYTHON) setup.py clean
	-rm -rf build *~ \#* *pyc .#*

install:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`
	[ -d $(BINDIR) ] || mkdir -p $(BINDIR)
	install -m 755 sepolicy.py $(BINDIR)/sepolicy
	-mkdir -p $(MANDIR)/man8
	install -m 644 *.8 $(MANDIR)/man8
	-mkdir -p $(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(BASHCOMPLETIONDIR)
