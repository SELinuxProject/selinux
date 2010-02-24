# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYLIBVER ?= $(shell python -c 'import sys;print "python%d.%d" % sys.version_info[0:2]')
PYINC ?= /usr/include/$(PYLIBVER)
PYLIB ?= /usr/lib/$(PYLIBVER)
PYTHONLIBDIR ?= $(LIBDIR)/$(PYLIBVER)
RUBYLIBVER ?= $(shell ruby -e 'print RUBY_VERSION.split(".")[0..1].join(".")')
RUBYPLATFORM ?= $(shell ruby -e 'print RUBY_PLATFORM')
RUBYINC ?= $(LIBDIR)/ruby/$(RUBYLIBVER)/$(RUBYPLATFORM)
RUBYINSTALL ?= $(LIBDIR)/ruby/site_ruby/$(RUBYLIBVER)/$(RUBYPLATFORM)
LIBBASE=$(shell basename $(LIBDIR))

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LIBA=libselinux.a 
TARGET=libselinux.so
LIBPC=libselinux.pc
SWIGIF= selinuxswig_python.i selinuxswig_python_exception.i
SWIGRUBYIF= selinuxswig_ruby.i
SWIGCOUT= selinuxswig_wrap.c
SWIGRUBYCOUT= selinuxswig_ruby_wrap.c
SWIGLOBJ:= $(patsubst %.c,%.lo,$(SWIGCOUT)) 
SWIGRUBYLOBJ:= $(patsubst %.c,%.lo,$(SWIGRUBYCOUT)) 
SWIGSO=_selinux.so
SWIGFILES=$(SWIGSO) selinux.py selinuxswig_python_exception.i
SWIGRUBYSO=_rubyselinux.so
LIBSO=$(TARGET).$(LIBVERSION)
AUDIT2WHYSO=audit2why.so

ifeq ($(DISABLE_AVC),y)
	UNUSED_SRCS+=avc.c avc_internal.c avc_sidtab.c mapping.c stringrep.c checkAccess.c
endif
ifeq ($(DISABLE_BOOL),y)
	UNUSED_SRCS+=booleans.c
endif
ifeq ($(DISABLE_RPM),y)
	UNUSED_SRCS+=rpm.c
endif

GENERATED=$(SWIGCOUT) $(SWIGRUBYCOUT)
SRCS= $(filter-out $(UNUSED_SRCS), $(filter-out audit2why.c $(GENERATED),$(wildcard *.c)))

OBJS= $(patsubst %.c,%.o,$(SRCS))
LOBJS= $(patsubst %.c,%.lo,$(SRCS))
CFLAGS ?= -Werror -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $(EMFLAGS)
RANLIB=ranlib

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
TLSFLAGS += -mno-tls-direct-seg-refs
endif

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./

SWIGRUBY = swig -Wall -ruby -o $(SWIGRUBYCOUT) -outdir ./

all: $(LIBA) $(LIBSO) $(LIBPC)

pywrap: all $(SWIGSO) $(AUDIT2WHYSO)

rubywrap: all $(SWIGRUBYSO)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(filter-out -Werror,$(CFLAGS)) -I$(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGRUBYLOBJ): $(SWIGRUBYCOUT)
	$(CC) $(filter-out -Werror,$(CFLAGS)) -I$(RUBYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $< -L. -lselinux -L$(LIBDIR) -Wl,-soname,$@

$(SWIGRUBYSO): $(SWIGRUBYLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -L. -lselinux -L$(LIBDIR) -Wl,-soname,$@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -ldl -L$(LIBDIR) -Wl,-soname,$(LIBSO),-z,defs,-z,relro
	ln -sf $@ $(TARGET) 

$(LIBPC): $(LIBPC).in
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):' < $< > $@

selinuxswig_python_exception.i: ../include/selinux/selinux.h
	bash exception.sh > $@ 

audit2why.lo: audit2why.c
	$(CC) $(CFLAGS) -I$(PYINC) -fPIC -DSHARED -c -o $@ $<

$(AUDIT2WHYSO): audit2why.lo
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -L. -lselinux ${LIBDIR}/libsepol.a -L$(LIBDIR) -Wl,-soname,$@

%.o:  %.c policy.h
	$(CC) $(CFLAGS) $(TLSFLAGS) -c -o $@ $<

%.lo:  %.c policy.h
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

$(SWIGCOUT): $(SWIGIF)
	$(SWIG) $^

$(SWIGRUBYCOUT): $(SWIGRUBYIF)
	$(SWIGRUBY) $^

swigify: $(SWIGIF)
	$(SWIG) $<

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	test -d $(LIBDIR)/pkgconfig || install -m 755 -d $(LIBDIR)/pkgconfig
	install -m 644 $(LIBPC) $(LIBDIR)/pkgconfig
	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

install-pywrap: pywrap
	test -d $(PYTHONLIBDIR)/site-packages/selinux || install -m 755 -d $(PYTHONLIBDIR)/site-packages/selinux
	install -m 755 $(SWIGSO) $(PYTHONLIBDIR)/site-packages/selinux
	install -m 755 $(AUDIT2WHYSO) $(PYTHONLIBDIR)/site-packages/selinux
	install -m 644  selinux.py $(PYTHONLIBDIR)/site-packages/selinux/__init__.py

install-rubywrap: rubywrap
	test -d $(RUBYINSTALL) || install -m 755 -d $(RUBYINSTALL) 
	install -m 755 $(SWIGRUBYSO) $(RUBYINSTALL)/selinux.so

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGSO) $(TARGET) $(AUDIT2WHYSO) *.o *.lo *~

distclean: clean
	rm -f $(GENERATED) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

