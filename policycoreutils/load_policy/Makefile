# Installation directories.
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= $(DESTDIR)$(PREFIX)/share/locale

CFLAGS ?= -Werror -Wall -W
override CFLAGS += $(LDFLAGS) -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
override LDLIBS += -lsepol -lselinux

TARGETS=$(patsubst %.c,%,$(sort $(wildcard *.c)))

all: $(TARGETS)

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 $(TARGETS) $(DESTDIR)$(SBINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 load_policy.8 $(DESTDIR)$(MANDIR)/man8/

clean:
	-rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
	/sbin/restorecon $(DESTDIR)$(SBINDIR)/load_policy 
