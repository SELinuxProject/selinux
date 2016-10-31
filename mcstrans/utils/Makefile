# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/sbin

ARCH = $(shell uname -i)
ifeq "$(ARCH)" "x86_64"
        # In case of 64 bit system, use these lines
        LIBDIR=/usr/lib64
else
ifeq "$(ARCH)" "i686"
        # In case of 32 bit system, use these lines
        LIBDIR=/usr/lib
else
ifeq "$(ARCH)" "i386"
        # In case of 32 bit system, use these lines
        LIBDIR=/usr/lib
endif
endif
endif


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

