# Support building the Python bindings multiple times, against various Python
# runtimes (e.g. Python 2 vs Python 3) by optionally prefixing the build
# targets with "PYPREFIX":
PYTHON ?= python
PYPREFIX ?= $(notdir $(PYTHON))
RUBY ?= ruby
RUBYPREFIX ?= $(notdir $(RUBY))

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYLIBVER ?= $(shell $(PYTHON) -c 'import sys;print("python%d.%d" % sys.version_info[0:2])')
PYINC ?= $(shell pkg-config --cflags $(PYPREFIX))
PYLIBDIR ?= $(LIBDIR)/$(PYLIBVER)
RUBYLIBVER ?= $(shell $(RUBY) -e 'print RUBY_VERSION.split(".")[0..1].join(".")')
RUBYPLATFORM ?= $(shell $(RUBY) -e 'print RUBY_PLATFORM')
RUBYINC ?= $(shell pkg-config --cflags ruby)
RUBYINSTALL ?= $(LIBDIR)/ruby/site_ruby/$(RUBYLIBVER)/$(RUBYPLATFORM)
LIBBASE ?= $(shell basename $(LIBDIR))

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LIBA=libselinux.a 
TARGET=libselinux.so
LIBPC=libselinux.pc
SWIGIF= selinuxswig_python.i selinuxswig_python_exception.i
SWIGRUBYIF= selinuxswig_ruby.i
SWIGCOUT= selinuxswig_wrap.c
SWIGPYOUT= selinux.py
SWIGRUBYCOUT= selinuxswig_ruby_wrap.c
SWIGLOBJ:= $(patsubst %.c,$(PYPREFIX)%.lo,$(SWIGCOUT))
SWIGRUBYLOBJ:= $(patsubst %.c,%.lo,$(SWIGRUBYCOUT)) 
SWIGSO=$(PYPREFIX)_selinux.so
SWIGFILES=$(SWIGSO) $(SWIGPYOUT)
SWIGRUBYSO=$(RUBYPREFIX)_selinux.so
LIBSO=$(TARGET).$(LIBVERSION)
AUDIT2WHYLOBJ=$(PYPREFIX)audit2why.lo
AUDIT2WHYSO=$(PYPREFIX)audit2why.so

ifeq ($(DISABLE_AVC),y)
	UNUSED_SRCS+=avc.c avc_internal.c avc_sidtab.c mapping.c stringrep.c checkAccess.c
endif
ifeq ($(DISABLE_BOOL),y)
	UNUSED_SRCS+=booleans.c
endif

GENERATED=$(SWIGCOUT) $(SWIGRUBYCOUT) selinuxswig_python_exception.i
SRCS= $(filter-out $(UNUSED_SRCS) $(GENERATED) audit2why.c, $(wildcard *.c))

MAX_STACK_SIZE=32768

OBJS= $(patsubst %.c,%.o,$(SRCS))
LOBJS= $(patsubst %.c,%.lo,$(SRCS))
CFLAGS ?= -O -Wall -W -Wundef -Wformat-y2k -Wformat-security -Winit-self -Wmissing-include-dirs \
          -Wunused -Wunknown-pragmas -Wstrict-aliasing -Wshadow -Wpointer-arith \
          -Wbad-function-cast -Wcast-align -Wwrite-strings -Wlogical-op -Waggregate-return \
          -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
          -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute \
          -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wvolatile-register-var \
          -Wdisabled-optimization -Wbuiltin-macro-redefined -Wpacked-bitfield-compat \
          -Wsync-nand -Wattributes -Wcoverage-mismatch -Wmultichar -Wcpp \
          -Wdeprecated-declarations -Wdiv-by-zero -Wdouble-promotion -Wendif-labels -Wextra \
          -Wformat-contains-nul -Wformat-extra-args -Wformat-zero-length -Wformat=2 -Wmultichar \
          -Wnormalized=nfc -Woverflow -Wpointer-to-int-cast -Wpragmas -Wsuggest-attribute=const \
          -Wsuggest-attribute=noreturn -Wsuggest-attribute=pure -Wtrampolines \
          -Wno-missing-field-initializers -Wno-sign-compare -Wjump-misses-init \
          -Wno-format-nonliteral -Wframe-larger-than=$(MAX_STACK_SIZE) -Wp,-D_FORTIFY_SOURCE=2 \
          -fstack-protector-all --param=ssp-buffer-size=4 -fexceptions \
          -fasynchronous-unwind-tables -fdiagnostics-show-option -funit-at-a-time \
          -fipa-pure-const -Wno-suggest-attribute=pure -Wno-suggest-attribute=const \
          -Werror -Wno-aggregate-return -Wno-redundant-decls

override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $(EMFLAGS)

SWIG_CFLAGS += -Wno-error -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter \
		-Wno-shadow -Wno-uninitialized -Wno-missing-prototypes -Wno-missing-declarations

RANLIB ?= ranlib

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
TLSFLAGS += -mno-tls-direct-seg-refs
endif

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./ $(EMFLAGS)

SWIGRUBY = swig -Wall -ruby -o $(SWIGRUBYCOUT) -outdir ./ $(EMFLAGS)

all: $(LIBA) $(LIBSO) $(LIBPC)

pywrap: all $(SWIGFILES) $(AUDIT2WHYSO)

rubywrap: all $(SWIGRUBYSO)

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGRUBYLOBJ): $(SWIGRUBYCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(RUBYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) -shared -o $@ $< -L. -lselinux $(LDFLAGS) -L$(LIBDIR)

$(SWIGRUBYSO): $(SWIGRUBYLOBJ)
	$(CC) $(CFLAGS) -shared -o $@ $^ -L. -lselinux $(LDFLAGS) -L$(LIBDIR)

$(LIBA): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^ -lpcre -ldl $(LDFLAGS) -L$(LIBDIR) -Wl,-soname,$(LIBSO),-z,defs,-z,relro
	ln -sf $@ $(TARGET) 

$(LIBPC): $(LIBPC).in ../VERSION
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):' < $< > $@

selinuxswig_python_exception.i: ../include/selinux/selinux.h
	bash exception.sh > $@ 

$(AUDIT2WHYLOBJ): audit2why.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) $(PYINC) -fPIC -DSHARED -c -o $@ $<

$(AUDIT2WHYSO): $(AUDIT2WHYLOBJ)
	$(CC) $(CFLAGS) -shared -o $@ $^ -L. $(LDFLAGS) -lselinux $(LIBDIR)/libsepol.a -L$(LIBDIR)

%.o:  %.c policy.h
	$(CC) $(CFLAGS) $(TLSFLAGS) -c -o $@ $<

%.lo:  %.c policy.h
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

$(SWIGCOUT): $(SWIGIF)
	$(SWIG) $<

$(SWIGPYOUT): $(SWIGCOUT)

$(SWIGRUBYCOUT): $(SWIGRUBYIF)
	$(SWIGRUBY) $<

swigify: $(SWIGIF)
	$(SWIG) $<

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	test -d $(LIBDIR)/pkgconfig || install -m 755 -d $(LIBDIR)/pkgconfig
	install -m 644 $(LIBPC) $(LIBDIR)/pkgconfig
	ln -sf --relative $(SHLIBDIR)/$(LIBSO) $(LIBDIR)/$(TARGET)

install-pywrap: pywrap
	test -d $(PYLIBDIR)/site-packages/selinux || install -m 755 -d $(PYLIBDIR)/site-packages/selinux
	install -m 755 $(SWIGSO) $(PYLIBDIR)/site-packages/selinux/_selinux.so
	install -m 755 $(AUDIT2WHYSO) $(PYLIBDIR)/site-packages/selinux/audit2why.so
	install -m 644 $(SWIGPYOUT) $(PYLIBDIR)/site-packages/selinux/__init__.py

install-rubywrap: rubywrap
	test -d $(RUBYINSTALL) || install -m 755 -d $(RUBYINSTALL) 
	install -m 755 $(SWIGRUBYSO) $(RUBYINSTALL)/selinux.so

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGRUBYLOBJ) $(SWIGSO) $(TARGET) $(AUDIT2WHYSO) *.o *.lo *~

distclean: clean
	rm -f $(GENERATED) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

.PHONY: all clean pywrap rubywrap swigify install install-pywrap install-rubywrap distclean
