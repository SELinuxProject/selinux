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
OBJS= $(patsubst %.c,%.o,$(sort $(wildcard *.c)))
LOBJS= $(patsubst %.c,%.lo,$(sort $(wildcard *.c)))
CFLAGS ?= -Werror -Wall -W -Wundef -Wshadow -Wmissing-format-attribute -O2

override CFLAGS += -I. -I../include -D_GNU_SOURCE

ifneq ($(DISABLE_CIL),y)
OBJS += $(sort $(patsubst %.c,%.o,$(sort $(wildcard $(CILDIR)/src/*.c)) $(CIL_GENERATED)))
LOBJS += $(sort $(patsubst %.c,%.lo,$(sort $(wildcard $(CILDIR)/src/*.c)) $(CIL_GENERATED)))
override CFLAGS += -I$(CILDIR)/include
endif

LD_SONAME_FLAGS=-soname,$(LIBSO),--version-script=$(LIBMAP),-z,defs

LN=ln
OS := $(shell uname)
ifeq ($(OS), Darwin)
LD_SONAME_FLAGS=-install_name,$(LIBSO)
LDFLAGS += -undefined dynamic_lookup
LN=gln
endif

all: $(LIBA) $(LIBSO) $(LIBPC)


$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(LIBSO): $(LOBJS) $(LIBMAP)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(LOBJS) -Wl,$(LD_SONAME_FLAGS)
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
$(CILDIR)/src/cil_lexer.o: $(CILDIR)/src/cil_lexer.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -fPIC -c -o $@ $<

$(CILDIR)/src/cil_lexer.lo: $(CILDIR)/src/cil_lexer.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -fPIC -DSHARED -c -o $@ $<

$(CILDIR)/src/cil_lexer.c: $(CILDIR)/src/cil_lexer.l
	$(LEX) -o $@ $<

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
	$(LN) -sf --relative $(SHLIBDIR)/$(LIBSO) $(LIBDIR)/$(TARGET)

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(LIBMAP) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) $(CIL_GENERATED)

indent:
	../../scripts/Lindent $(wildcard *.[ch])

