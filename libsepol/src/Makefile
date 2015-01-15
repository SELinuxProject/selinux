# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
RANLIB ?= ranlib
LIBBASE ?= $(shell basename $(LIBDIR))
CILDIR ?= ../cil

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LEX = flex
CIL_GENERATED = $(CILDIR)/src/cil_lexer.c

LIBA=libsepol.a 
TARGET=libsepol.so
LIBPC=libsepol.pc
LIBMAP=libsepol.map
LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(wildcard *.c))
LOBJS= $(patsubst %.c,%.lo,$(wildcard *.c))
CFLAGS ?= -Werror -Wall -W -Wundef -Wshadow -Wmissing-format-attribute -O2

override CFLAGS += -I. -I../include -D_GNU_SOURCE

ifneq ($(DISABLE_CIL),y)
OBJS += $(sort $(patsubst %.c,%.o,$(wildcard $(CILDIR)/src/*.c) $(CIL_GENERATED)))
LOBJS += $(sort $(patsubst %.c,%.lo,$(wildcard $(CILDIR)/src/*.c) $(CIL_GENERATED)))
override CFLAGS += -I$(CILDIR)/include
endif


all: $(LIBA) $(LIBSO) $(LIBPC)


$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(LIBSO): $(LOBJS) $(LIBMAP)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(LOBJS) -Wl,-soname,$(LIBSO),--version-script=$(LIBMAP),-z,defs
	ln -sf $@ $(TARGET) 

$(LIBPC): $(LIBPC).in ../VERSION
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):' < $< > $@

$(LIBMAP): $(LIBMAP).in
ifneq ($(DISABLE_CIL),y)
	cp $< $@
else
	sed -e '/^\s*cil_/d' < $< > $@
endif

ifneq ($(DISABLE_CIL),y)
$(CILDIR)/src/cil_lexer.c: $(CILDIR)/src/cil_lexer.l
	$(LEX) -t $< > $@
endif

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
	ln -sf --relative $(SHLIBDIR)/$(LIBSO) $(LIBDIR)/$(TARGET)

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) $(CIL_GENERATED)

indent:
	../../scripts/Lindent $(wildcard *.[ch])

