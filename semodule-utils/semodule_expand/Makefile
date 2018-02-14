# Installation directories.
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol

all: semodule_expand

semodule_expand:  semodule_expand.o 

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 semodule_expand $(DESTDIR)$(BINDIR)
	test -d $(DESTDIR)$(MANDIR)/man8 || install -m 755 -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 semodule_expand.8 $(DESTDIR)$(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule_expand *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

