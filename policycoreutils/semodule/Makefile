# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = -lsepol -lselinux -lsemanage -L$(LIBDIR)
SEMODULE_OBJS = semodule.o

.PHONY: all semodule_path
all: semodule semodule_path

semodule_path:
	@echo -n $(SBINDIR) > ../scripts/semodule_path

semodule: $(SEMODULE_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	-mkdir -p $(SBINDIR)
	install -m 755 semodule $(SBINDIR)
	test -d $(MANDIR)/man8 || install -m 755 -d $(MANDIR)/man8
	install -m 644 semodule.8 $(MANDIR)/man8/

relabel:

clean:
	-rm -f semodule *.o ../scripts/semodule_path

indent:
	../../scripts/Lindent $(wildcard *.[ch])

