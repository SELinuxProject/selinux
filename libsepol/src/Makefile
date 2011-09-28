# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
LIBBASE=$(shell basename $(LIBDIR))

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LIBA=libsepol.a 
TARGET=libsepol.so
LIBPC=libsepol.pc
LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(wildcard *.c))
LOBJS= $(patsubst %.c,%.lo,$(wildcard *.c))
CFLAGS ?= -Werror -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I. -I../include -D_GNU_SOURCE

all: $(LIBA) $(LIBSO) $(LIBPC)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -Wl,-soname,$(LIBSO),--version-script=libsepol.map,-z,defs
	ln -sf $@ $(TARGET) 

$(LIBPC): $(LIBPC).in ../VERSION
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):' < $< > $@

%.o:  %.c 
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

install: all
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	test -d $(LIBDIR)/pkgconfig || install -m 755 -d $(LIBDIR)/pkgconfig
	install -m 644 $(LIBPC) $(LIBDIR)/pkgconfig
	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET)

indent:
	../../scripts/Lindent $(wildcard *.[ch])

