#
# Makefile for the PO files (translation) catalog
#

PREFIX ?= /usr

# What is this package?
NLSPACKAGE	= gui
POTFILE		= $(NLSPACKAGE).pot
INSTALL		= /usr/bin/install -c -p
INSTALL_DATA	= $(INSTALL) -m 644
INSTALL_DIR	= /usr/bin/install -d

# destination directory
INSTALL_NLS_DIR = $(PREFIX)/share/locale

# PO catalog handling
MSGMERGE	= msgmerge
MSGMERGE_FLAGS	= -q
XGETTEXT	= xgettext --default-domain=$(NLSPACKAGE)
MSGFMT		= msgfmt

# All possible linguas
PO_LINGUAS := $(sort $(patsubst %.po,%,$(wildcard *.po)))

# Only the files matching what the user has set in LINGUAS
USER_LINGUAS := $(filter $(patsubst %,%%,$(LINGUAS)),$(PO_LINGUAS))

# if no valid LINGUAS, build all languages
USE_LINGUAS := $(if $(USER_LINGUAS),$(USER_LINGUAS),$(PO_LINGUAS))

POFILES		= $(patsubst %,%.po,$(USE_LINGUAS))
MOFILES		= $(patsubst %.po,%.mo,$(POFILES))
POTFILES  = $(shell cat POTFILES)

#default:: clean

all::  $(MOFILES)

$(POTFILE): $(POTFILES)
	$(XGETTEXT) --keyword=_ --keyword=N_ $(POTFILES)
	@if cmp -s $(NLSPACKAGE).po $(POTFILE); then \
	    rm -f $(NLSPACKAGE).po; \
	else \
	    mv -f $(NLSPACKAGE).po $(POTFILE); \
	fi; \


refresh-po: Makefile
	for cat in $(POFILES); do \
		lang=`basename $$cat .po`; \
		if $(MSGMERGE) $(MSGMERGE_FLAGS) $$lang.po $(POTFILE) > $$lang.pot ; then \
			mv -f $$lang.pot $$lang.po ; \
			echo "$(MSGMERGE) of $$lang succeeded" ; \
		else \
			echo "$(MSGMERGE) of $$lang failed" ; \
			rm -f $$lang.pot ; \
		fi \
	done

clean:
	@rm -fv *mo *~ .depend
	@rm -rf tmp

install: $(MOFILES)
	@for n in $(MOFILES); do \
	    l=`basename $$n .mo`; \
	    $(INSTALL_DIR) $(DESTDIR)$(INSTALL_NLS_DIR)/$$l/LC_MESSAGES; \
	    $(INSTALL_DATA) --verbose $$n $(DESTDIR)$(INSTALL_NLS_DIR)/$$l/LC_MESSAGES/selinux-$(NLSPACKAGE).mo; \
	done

%.mo: %.po
	$(MSGFMT) -o $@ $<
report:
	@for cat in $(wildcard *.po); do \
                echo -n "$$cat: "; \
                msgfmt -v --statistics -o /dev/null $$cat; \
        done

.PHONY: missing depend

relabel:

test:
