# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
USRSBINDIR ?= $(PREFIX)/sbin
SBINDIR ?= $(DESTDIR)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= $(PREFIX)/share/locale

.PHONY: all genhomedircon
all: fixfiles genhomedircon chcat

genhomedircon:
	@echo "#!/bin/sh" > genhomedircon
	@echo >> genhomedircon
	@if [ ! -e semodule_path ]; then echo -n "$(USRSBINDIR)/" >> genhomedircon; fi
	@if [ -e semodule_path ]; then echo -n "`cat semodule_path`/" >> genhomedircon; fi
	@echo "semodule -Bn" >> genhomedircon

install: all
	-mkdir -p $(BINDIR)
	install -m 755 chcat $(BINDIR)
	install -m 755 fixfiles $(SBINDIR)
	install -m 755 genhomedircon $(USRSBINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 fixfiles.8 $(MANDIR)/man8/
	install -m 644 genhomedircon.8 $(MANDIR)/man8/
	install -m 644 chcat.8 $(MANDIR)/man8/

clean:
	rm -f genhomedircon

indent:

relabel:
