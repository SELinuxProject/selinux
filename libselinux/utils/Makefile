# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/sbin
_BINDIR ?= $(DESTDIR)/sbin

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I../include -D_GNU_SOURCE $(EMFLAGS)
LDLIBS += -L../src -lselinux -L$(LIBDIR)

TARGETS=$(patsubst %.c,%,$(wildcard *.c))


ifeq ($(DISABLE_AVC),y)
	UNUSED_TARGETS+=compute_av compute_create compute_member compute_relabel
endif
ifeq ($(DISABLE_BOOL),y)
	UNUSED_TARGETS+=getsebool togglesebool
endif
TARGETS:= $(filter-out $(UNUSED_TARGETS) matchpathcon, $(TARGETS))

all: $(TARGETS) matchpathcon

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)
	-mkdir -p $(_BINDIR)
	install -m 755 matchpathcon $(_BINDIR)
	(cd $(BINDIR); 	ln -fs ../../sbin/matchpathcon)
clean:
	rm -f $(TARGETS) matchpathcon *.o *~

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:

