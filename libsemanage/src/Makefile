# Support building the Python bindings multiple times, against various Python
# runtimes (e.g. Python 2 vs Python 3) by optionally prefixing the build
# targets with "PYPREFIX":
PYTHON ?= python
PYPREFIX ?= $(notdir $(PYTHON))
RUBY ?= ruby
RUBYPREFIX ?= $(notdir $(RUBY))
PKG_CONFIG ?= pkg-config

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYINC ?= $(shell $(PKG_CONFIG) --cflags $(PYPREFIX))
PYLIBS ?= $(shell $(PKG_CONFIG) --libs $(PYPREFIX))
PYSITEDIR ?= $(DESTDIR)$(shell $(PYTHON) -c 'import site; print(site.getsitepackages()[0])')
PYCEXT ?= $(shell $(PYTHON) -c 'import imp;print([s for s,m,t in imp.get_suffixes() if t == imp.C_EXTENSION][0])')
RUBYINC ?= $(shell $(RUBY) -e 'puts "-I" + RbConfig::CONFIG["rubyarchhdrdir"] + " -I" + RbConfig::CONFIG["rubyhdrdir"]')
RUBYLIBS ?= $(shell $(RUBY) -e 'puts "-L" + RbConfig::CONFIG["libdir"] + " -lruby"')
RUBYINSTALL ?= $(DESTDIR)$(shell $(RUBY) -e 'puts RbConfig::CONFIG["vendorarchdir"]')

LIBBASE=$(shell basename $(LIBDIR))

DEFAULT_SEMANAGE_CONF_LOCATION=$(DESTDIR)/etc/selinux/semanage.conf

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow -Werror
	export LDFLAGS = -g
endif

LEX = flex
LFLAGS = -s
YACC = bison
YFLAGS = -d

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LIBA=libsemanage.a
TARGET=libsemanage.so
LIBPC=libsemanage.pc
SWIGIF= semanageswig_python.i semanageswig_python_exception.i
SWIGRUBYIF= semanageswig_ruby.i
SWIGCOUT= semanageswig_wrap.c
SWIGRUBYCOUT= semanageswig_ruby_wrap.c
SWIGLOBJ:= $(patsubst %.c,$(PYPREFIX)%.lo,$(SWIGCOUT))
SWIGRUBYLOBJ:= $(patsubst %.c,$(RUBYPREFIX)%.lo,$(SWIGRUBYCOUT)) 
SWIGSO=$(PYPREFIX)_semanage.so
SWIGFILES=$(SWIGSO) semanage.py 
SWIGRUBYSO=$(RUBYPREFIX)_semanage.so
LIBSO=$(TARGET).$(LIBVERSION)

GENERATED=$(SWIGCOUT) $(SWIGRUBYCOUT) semanageswig_python_exception.i $(wildcard conf-*.[ch])
SRCS= $(filter-out $(GENERATED),$(sort $(wildcard *.c)))

OBJS= $(patsubst %.c,%.o,$(SRCS)) conf-scan.o conf-parse.o
LOBJS= $(patsubst %.c,%.lo,$(SRCS)) conf-scan.lo conf-parse.lo
CFLAGS ?= -Werror -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wmissing-format-attribute

SWIG_CFLAGS += -Wno-error -Wno-unused-but-set-variable -Wno-unused-variable -Wno-shadow \
		-Wno-unused-parameter

override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE 
RANLIB ?= ranlib

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./

SWIGRUBY = swig -Wall -ruby -o $(SWIGRUBYCOUT) -outdir ./

all: $(LIBA) $(LIBSO) $(LIBPC)

pywrap: all $(SWIGSO)

rubywrap: all $(SWIGRUBYSO)

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGRUBYLOBJ): $(SWIGRUBYCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(RUBYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $< -L. -lsemanage $(PYLIBS) -L$(LIBDIR)

$(SWIGRUBYSO): $(SWIGRUBYLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -L. -lsemanage $(RUBYLIBS) -L$(LIBDIR)

$(LIBA): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -lsepol -laudit -lselinux -lbz2 -L$(LIBDIR) -Wl,-soname,$(LIBSO),--version-script=libsemanage.map,-z,defs
	ln -sf $@ $(TARGET)

$(LIBPC): $(LIBPC).in ../VERSION
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):' < $< > $@

semanageswig_python_exception.i: ../include/semanage/semanage.h
	bash -e exception.sh > $@ || (rm -f $@ ; false)

conf-scan.c: conf-scan.l conf-parse.h
	$(LEX) $(LFLAGS) -o $@ $<

conf-parse.c: conf-parse.y
	$(YACC) $(YFLAGS) -o $@ $<

conf-parse.h: conf-parse.c

%.o:  %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

conf-parse.o:  conf-parse.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -c -o $@ $<

conf-parse.lo:  conf-parse.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -fPIC -DSHARED -c -o $@ $<

conf-scan.o:  conf-scan.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -c -o $@ $<

conf-scan.lo:  conf-scan.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) -fPIC -DSHARED -c -o $@ $<

$(SWIGCOUT): $(SWIGIF)
	$(SWIG) $<

$(SWIGRUBYCOUT): $(SWIGRUBYIF)
	$(SWIGRUBY) $<

swigify: $(SWIGIF)
	$(SWIG) $<

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	install -m 755 $(LIBSO) $(LIBDIR)
	test -d $(LIBDIR)/pkgconfig || install -m 755 -d $(LIBDIR)/pkgconfig
	install -m 644 $(LIBPC) $(LIBDIR)/pkgconfig
	test -f $(DEFAULT_SEMANAGE_CONF_LOCATION) || install -m 644 -D semanage.conf $(DEFAULT_SEMANAGE_CONF_LOCATION)
	cd $(LIBDIR) && ln -sf $(LIBSO) $(TARGET)

install-pywrap: pywrap 
	test -d $(PYSITEDIR) || install -m 755 -d $(PYSITEDIR)
	install -m 755 $(SWIGSO) $(PYSITEDIR)/_semanage$(PYCEXT)
	install -m 644 semanage.py $(PYSITEDIR)


install-rubywrap: rubywrap
	test -d $(RUBYINSTALL) || install -m 755 -d $(RUBYINSTALL) 
	install -m 755 $(SWIGRUBYSO) $(RUBYINSTALL)/semanage.so

relabel:
	/sbin/restorecon $(LIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGSO) $(SWIGRUBYSO) $(TARGET) conf-parse.c conf-parse.h conf-scan.c *.o *.lo *~

distclean: clean
	rm -f $(GENERATED) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

.PHONY: all clean pywrap rubywrap swigify install install-pywrap install-rubywrap distclean
