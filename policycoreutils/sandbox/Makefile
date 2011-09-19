# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INITDIR ?= $(DESTDIR)/etc/rc.d/init.d/
SYSCONFDIR ?= $(DESTDIR)/etc/sysconfig
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale
SHAREDIR ?= $(PREFIX)/share/sandbox
override CFLAGS += $(LDFLAGS) -I$(PREFIX)/include -DPACKAGE="\"policycoreutils\"" -Wall -Werror -Wextra
LDLIBS += -lcgroup -lselinux -lcap-ng

all: sandbox seunshare sandboxX.sh start

seunshare: seunshare.o $(EXTRA_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 sandbox $(BINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 644 sandbox.8 $(MANDIR)/man8/
	install -m 644 seunshare.8 $(MANDIR)/man8/
	-mkdir -p $(MANDIR)/man5
	install -m 644 sandbox.conf.5 $(MANDIR)/man5/
	-mkdir -p $(SBINDIR)
	install -m 4755 seunshare $(SBINDIR)/
	-mkdir -p $(SHAREDIR)
	install -m 755 sandboxX.sh $(SHAREDIR)
	install -m 755 start $(SHAREDIR)
	-mkdir -p $(INITDIR)
	install -m 755 sandbox.init $(INITDIR)/sandbox
	-mkdir -p $(SYSCONFDIR)
	install -m 644 sandbox.conf $(SYSCONFDIR)/sandbox

test:
	@python test_sandbox.py -v

clean:
	-rm -f seunshare *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
