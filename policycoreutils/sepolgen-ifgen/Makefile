# Installation directories.
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = $(LIBDIR)/libsepol.a

all: sepolgen-ifgen-attr-helper

sepolgen-ifgen-attr-helper: sepolgen-ifgen-attr-helper.o

install: all
	-mkdir -p $(BINDIR)
	install -m 755 sepolgen-ifgen-attr-helper $(BINDIR)

clean:
	rm -f *~ *.o sepolgen-ifgen-attr-helper

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: ;
