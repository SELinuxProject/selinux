# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale

CFLAGS ?= -Werror -Wall -W
override CFLAGS += $(LDFLAGS) -I$(PREFIX)/include -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
LDLIBS += -lsepol -lselinux -L$(PREFIX)/lib

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS)

install: all
	-mkdir -p $(SBINDIR)
	install -m 755 $(TARGETS) $(SBINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 644 load_policy.8 $(MANDIR)/man8/

clean:
	-rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
	/sbin/restorecon $(SBINDIR)/load_policy 
