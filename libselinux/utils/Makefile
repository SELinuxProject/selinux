# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/sbin

CFLAGS ?= -Wall
override CFLAGS += -I../include -D_GNU_SOURCE $(EMFLAGS)
LDLIBS += -L../src -lselinux -L$(LIBDIR)

TARGETS=$(patsubst %.c,%,$(wildcard *.c))
ifeq ($(DISABLE_AVC),y)
	UNUSED_TARGETS+=compute_av compute_create compute_member compute_relabel
endif
ifeq ($(DISABLE_BOOL),y)
	UNUSED_TARGETS+=getsebool togglesebool
endif
TARGETS:= $(filter-out $(UNUSED_TARGETS), $(TARGETS))

all: $(TARGETS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)

clean:
	rm -f $(TARGETS) *.o 

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:

