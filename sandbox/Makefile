PYTHON ?= python

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
SYSCONFDIR ?= $(DESTDIR)/etc/sysconfig
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
SHAREDIR ?= $(PREFIX)/share/sandbox
override CFLAGS += -DPACKAGE="\"policycoreutils\"" -Wall -Werror -Wextra -W
override LDLIBS += -lselinux -lcap-ng
SEUNSHARE_OBJS = seunshare.o

all: sandbox seunshare sandboxX.sh start

seunshare: $(SEUNSHARE_OBJS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 sandbox $(BINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 sandbox.8 $(MANDIR)/man8/
	install -m 644 seunshare.8 $(MANDIR)/man8/
	-mkdir -p $(MANDIR)/man5
	install -m 644 sandbox.5 $(MANDIR)/man5/
	-mkdir -p $(SBINDIR)
	install -m 4755 seunshare $(SBINDIR)/
	-mkdir -p $(SHAREDIR)
	install -m 755 sandboxX.sh $(SHAREDIR)
	install -m 755 start $(SHAREDIR)
	-mkdir -p $(SYSCONFDIR)
	install -m 644 sandbox.conf $(SYSCONFDIR)/sandbox

test:
	@$(PYTHON) test_sandbox.py -v

clean:
	-rm -f seunshare *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
