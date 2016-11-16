# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/sbin

CFLAGS ?= -Wall
override CFLAGS += -I../src -D_GNU_SOURCE
LDLIBS += -L../src ../src/mcstrans.o ../src/mls_level.o -lselinux -lpcre $(LIBDIR)/libsepol.a

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS) 

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)

test:
	./mlstrans-test-runner.py ../test/*.test

clean:
	rm -f $(TARGETS) *.o *~ \#*

relabel:

