PYTHON ?= python3

# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
SYSCONFDIR ?= /etc/sysconfig
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
SHAREDIR ?= $(PREFIX)/share/sandbox
override CFLAGS += -DPACKAGE="\"policycoreutils\"" -Wall -Werror -Wextra -W
override LDLIBS += -lselinux -lcap-ng
SEUNSHARE_OBJS = seunshare.o

all: sandbox seunshare sandboxX.sh start

seunshare: $(SEUNSHARE_OBJS)

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 sandbox $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 644 sandbox.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 seunshare.8 $(DESTDIR)$(MANDIR)/man8/
	-mkdir -p $(DESTDIR)$(MANDIR)/man5
	install -m 644 sandbox.5 $(DESTDIR)$(MANDIR)/man5/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man5 ; \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.5 $(DESTDIR)$(MANDIR)/$${lang}/man5/ ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 4755 seunshare $(DESTDIR)$(SBINDIR)/
	-mkdir -p $(DESTDIR)$(SHAREDIR)
	install -m 755 sandboxX.sh $(DESTDIR)$(SHAREDIR)
	install -m 755 start $(DESTDIR)$(SHAREDIR)
	-mkdir -p $(DESTDIR)$(SYSCONFDIR)
	install -m 644 sandbox.conf $(DESTDIR)$(SYSCONFDIR)/sandbox

test:
	@$(PYTHON) test_sandbox.py -v

clean:
	-rm -f seunshare *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
