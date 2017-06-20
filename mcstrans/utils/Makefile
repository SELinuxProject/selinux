# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

CFLAGS ?= -Wall
override CFLAGS += -I../src -D_GNU_SOURCE
override LDLIBS += -lselinux -lpcre

TARGETS=$(patsubst %.c,%,$(sort $(wildcard *.c)))

all: $(TARGETS)

$(TARGETS): ../src/mcstrans.o ../src/mls_level.o $(LIBSEPOLA)

install: all
	-mkdir -p $(SBINDIR)
	install -m 755 $(TARGETS) $(SBINDIR)

test:
	./mlstrans-test-runner.py ../test/*.test

clean:
	rm -f $(TARGETS) *.o *~ \#*

relabel:

