PYTHON ?= python3

# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
BASHCOMPLETIONDIR ?= $(PREFIX)/share/bash-completion/completions
CFLAGS ?= -Wall -Werror -Wextra -W
override CFLAGS += -DPACKAGE="policycoreutils" -DSHARED -shared

BASHCOMPLETIONS=sepolicy-bash-completion.sh

all: python-build

python-build:
	$(PYTHON) setup.py build

clean:
	$(PYTHON) setup.py clean
	-rm -rf build *~ \#* *pyc .#* sepolicy.egg-info/

sepolgen:
	ln -sf sepolicy sepolgen

test:
	@$(PYTHON) test_sepolicy.py -v

install:
	$(PYTHON) -m pip install --prefix=$(PREFIX) `test -n "$(DESTDIR)" && echo --root $(DESTDIR) --ignore-installed --no-deps` $(PYTHON_SETUP_ARGS) .
	[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 sepolicy.py $(DESTDIR)$(BINDIR)/sepolicy
	(cd $(DESTDIR)$(BINDIR); ln -sf sepolicy sepolgen)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 644 *.8 $(DESTDIR)$(MANDIR)/man8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	-mkdir -p $(DESTDIR)$(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(DESTDIR)$(BASHCOMPLETIONDIR)/sepolicy

relabel:
