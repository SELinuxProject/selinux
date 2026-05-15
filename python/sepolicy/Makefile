PYTHON ?= python3

# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
BASHCOMPLETIONDIR ?= $(PREFIX)/share/bash-completion/completions
CFLAGS ?= -Wall -Werror -Wextra -W
override CFLAGS += -DPACKAGE="policycoreutils" -DSHARED -shared

BASHCOMPLETIONS=sepolicy-bash-completion.sh

all: python-build

python-build:
	$(PYTHON) -m pip install build wheel setuptools
	$(PYTHON) -m build --no-isolation --wheel .

clean:
	-rm -rf build dist *.egg-info *~ \#* *pyc .#*

sepolgen:
	ln -sf sepolicy sepolgen

test:
	@$(PYTHON) test_sepolicy.py -v

install: python-build
	$(PYTHON) -m pip install --no-build-isolation --force-reinstall --prefix=$(PREFIX) `test -n "$(DESTDIR)" && echo --root $(DESTDIR) --ignore-installed --no-deps` dist/*.whl
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
