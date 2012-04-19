#
# Makefile for the PO files (translation) catalog
#

TOP	 = ../..

# What is this package?
NLSPACKAGE	= policycoreutils
POTFILE		= $(NLSPACKAGE).pot
INSTALL		= /usr/bin/install -c -p
INSTALL_DATA	= $(INSTALL) -m 644
INSTALL_DIR	= /usr/bin/install -d

# destination directory
INSTALL_NLS_DIR = $(DESTDIR)/usr/share/locale

# PO catalog handling
MSGMERGE	= msgmerge
MSGMERGE_FLAGS	= -q
XGETTEXT	= xgettext --default-domain=$(NLSPACKAGE)
MSGFMT		= msgfmt

# What do we need to do
POFILES		= $(wildcard *.po)
MOFILES		= $(patsubst %.po,%.mo,$(POFILES))
POTFILES = \
	../run_init/open_init_pty.c \
	../run_init/run_init.c \
	../semodule_link/semodule_link.c \
	../audit2allow/audit2allow \
	../semanage/seobject.py \
	../setsebool/setsebool.c \
	../newrole/newrole.c \
	../load_policy/load_policy.c \
	../sestatus/sestatus.c \
	../semodule/semodule.c \
	../setfiles/setfiles.c \
	../semodule_package/semodule_package.c \
	../semodule_deps/semodule_deps.c \
	../semodule_expand/semodule_expand.c \
	../scripts/chcat \
	../scripts/fixfiles \
	../restorecond/stringslist.c \
	../restorecond/restorecond.h \
	../restorecond/utmpwatcher.h \
	../restorecond/stringslist.h \
	../restorecond/restorecond.c \
	../restorecond/utmpwatcher.c \
	../gui/booleansPage.py \
	../gui/fcontextPage.py \
	../gui/loginsPage.py \
	../gui/mappingsPage.py \
	../gui/modulesPage.py \
	../gui/polgen.glade \
	../gui/polgengui.py \
	../gui/polgen.py \
	../gui/portsPage.py \
	../gui/selinux.tbl \
	../gui/semanagePage.py \
	../gui/statusPage.py \
	../gui/system-config-selinux.glade \
	../gui/system-config-selinux.py \
	../gui/usersPage.py \
	../gui/templates/executable.py \
	../gui/templates/__init__.py \
	../gui/templates/network.py \
	../gui/templates/rw.py \
	../gui/templates/script.py \
	../gui/templates/semodule.py \
	../gui/templates/tmp.py \
	../gui/templates/user.py \
	../gui/templates/var_lib.py \
	../gui/templates/var_log.py \
	../gui/templates/var_run.py \
	../gui/templates/var_spool.py \
	../secon/secon.c

#default:: clean

all::  update-po $(MOFILES)

$(POTFILE): $(POTFILES) 
	$(XGETTEXT) --keyword=_ --keyword=N_ $(POTFILES)
	@if cmp -s $(NLSPACKAGE).po $(POTFILE); then \
	    rm -f $(NLSPACKAGE).po; \
	else \
	    mv -f $(NLSPACKAGE).po $(POTFILE); \
	fi; \

update-po: Makefile $(POTFILE) refresh-po

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
	    $(INSTALL_DIR) $(INSTALL_NLS_DIR)/$$l/LC_MESSAGES; \
	    $(INSTALL_DATA) --verbose $$n $(INSTALL_NLS_DIR)/$$l/LC_MESSAGES/$(NLSPACKAGE).mo; \
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
