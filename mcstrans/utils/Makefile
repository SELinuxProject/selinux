# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/sbin
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

CFLAGS ?= -Wall
override CFLAGS += -I../src -D_GNU_SOURCE
LDLIBS += -lselinux -lpcre

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS)

$(TARGETS): ../src/mcstrans.o ../src/mls_level.o $(LIBSEPOLA)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)

test:
	./mlstrans-test-runner.py ../test/*.test

clean:
	rm -f $(TARGETS) *.o *~ \#*

relabel:

