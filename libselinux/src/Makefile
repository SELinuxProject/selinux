# Support building the Python bindings multiple times, against various Python
# runtimes (e.g. Python 2 vs Python 3) by optionally prefixing the build
# targets with "PYPREFIX":
PYTHON ?= python
PYPREFIX ?= $(shell $(PYTHON) -c 'import sys;print("python-%d.%d" % sys.version_info[:2])')
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
RUBYLIBS ?= $(shell $(RUBY) -e 'puts "-L" + RbConfig::CONFIG["libdir"] + " -L" + RbConfig::CONFIG["archlibdir"] + " " + RbConfig::CONFIG["LIBRUBYARG_SHARED"]')
RUBYINSTALL ?= $(DESTDIR)$(shell $(RUBY) -e 'puts RbConfig::CONFIG["vendorarchdir"]')
LIBBASE ?= $(shell basename $(LIBDIR))
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

OS ?= $(shell uname)

ifeq ($(shell $(CC) -v 2>&1 | grep "clang"),)
COMPILER ?= gcc
else
COMPILER ?= clang
endif

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

GENERATED=$(SWIGCOUT) $(SWIGRUBYCOUT) selinuxswig_python_exception.i
SRCS= $(filter-out $(GENERATED) audit2why.c, $(sort $(wildcard *.c)))

MAX_STACK_SIZE=32768

ifeq ($(COMPILER), gcc)
EXTRA_CFLAGS = -fipa-pure-const -Wlogical-op -Wpacked-bitfield-compat -Wsync-nand \
	-Wcoverage-mismatch -Wcpp -Wformat-contains-nul -Wnormalized=nfc -Wsuggest-attribute=const \
	-Wsuggest-attribute=noreturn -Wsuggest-attribute=pure -Wtrampolines -Wjump-misses-init \
	-Wno-suggest-attribute=pure -Wno-suggest-attribute=const -Wp,-D_FORTIFY_SOURCE
else
EXTRA_CFLAGS = -Wunused-command-line-argument
endif

OBJS= $(patsubst %.c,%.o,$(SRCS))
LOBJS= $(patsubst %.c,%.lo,$(SRCS))
CFLAGS ?= -O -Wall -W -Wundef -Wformat-y2k -Wformat-security -Winit-self -Wmissing-include-dirs \
          -Wunused -Wunknown-pragmas -Wstrict-aliasing -Wshadow -Wpointer-arith \
          -Wbad-function-cast -Wcast-align -Wwrite-strings -Waggregate-return \
          -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
          -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute \
          -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wvolatile-register-var \
          -Wdisabled-optimization -Wbuiltin-macro-redefined \
          -Wattributes -Wmultichar \
          -Wdeprecated-declarations -Wdiv-by-zero -Wdouble-promotion -Wendif-labels -Wextra \
          -Wformat-extra-args -Wformat-zero-length -Wformat=2 -Wmultichar \
          -Woverflow -Wpointer-to-int-cast -Wpragmas \
          -Wno-missing-field-initializers -Wno-sign-compare \
          -Wno-format-nonliteral -Wframe-larger-than=$(MAX_STACK_SIZE) \
          -fstack-protector-all --param=ssp-buffer-size=4 -fexceptions \
          -fasynchronous-unwind-tables -fdiagnostics-show-option -funit-at-a-time \
          -Werror -Wno-aggregate-return -Wno-redundant-decls \
          $(EXTRA_CFLAGS)

LD_SONAME_FLAGS=-soname,$(LIBSO),-z,defs,-z,relro

ifeq ($(OS), Darwin)
override CFLAGS += -I/opt/local/include
override LDFLAGS += -L/opt/local/lib -undefined dynamic_lookup
LD_SONAME_FLAGS=-install_name,$(LIBSO)
endif

PCRE_LDLIBS ?= -lpcre

override CFLAGS += -I../include -D_GNU_SOURCE $(DISABLE_FLAGS) $(PCRE_CFLAGS)

SWIG_CFLAGS += -Wno-error -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter \
		-Wno-shadow -Wno-uninitialized -Wno-missing-prototypes -Wno-missing-declarations

RANLIB ?= ranlib

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
TLSFLAGS += -mno-tls-direct-seg-refs
endif

ifeq ($(ANDROID_HOST),y)
DISABLE_FLAGS+= -DNO_MEDIA_BACKEND -DNO_DB_BACKEND -DNO_X_BACKEND \
	-DBUILD_HOST
SRCS= callbacks.c freecon.c label.c label_file.c \
	label_backends_android.c regex.c label_support.c \
	matchpathcon.c setrans_client.c sha1.c booleans.c
else
DISABLE_FLAGS+= -DNO_ANDROID_BACKEND
SRCS:= $(filter-out label_backends_android.c, $(SRCS))
endif

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./ $(DISABLE_FLAGS)

SWIGRUBY = swig -Wall -ruby -o $(SWIGRUBYCOUT) -outdir ./ $(DISABLE_FLAGS)

all: $(LIBA) $(LIBSO) $(LIBPC)

pywrap: all $(SWIGFILES) $(AUDIT2WHYSO)

rubywrap: all $(SWIGRUBYSO)

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGRUBYLOBJ): $(SWIGRUBYCOUT)
	$(CC) $(CFLAGS) $(SWIG_CFLAGS) $(RUBYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -shared -o $@ $< -lselinux $(PYLIBS)

$(SWIGRUBYSO): $(SWIGRUBYLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -shared -o $@ $^ -lselinux $(RUBYLIBS)

$(LIBA): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ $(PCRE_LDLIBS) -ldl -Wl,$(LD_SONAME_FLAGS)
	ln -sf $@ $(TARGET)

$(LIBPC): $(LIBPC).in ../VERSION
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBBASE):; s:@includedir@:$(INCLUDEDIR):; s:@PCRE_MODULE@:$(PCRE_MODULE):' < $< > $@

selinuxswig_python_exception.i: ../include/selinux/selinux.h
	bash -e exception.sh > $@ || (rm -f $@ ; false)

$(AUDIT2WHYLOBJ): audit2why.c
	$(CC) $(filter-out -Werror, $(CFLAGS)) $(PYINC) -fPIC -DSHARED -c -o $@ $<

$(AUDIT2WHYSO): $(AUDIT2WHYLOBJ) $(LIBSEPOLA)
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -shared -o $@ $^ -lselinux $(PYLIBS)

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
	test -d $(PYSITEDIR)/selinux || install -m 755 -d $(PYSITEDIR)/selinux
	install -m 755 $(SWIGSO) $(PYSITEDIR)/_selinux$(PYCEXT)
	install -m 755 $(AUDIT2WHYSO) $(PYSITEDIR)/selinux/audit2why$(PYCEXT)
	install -m 644 $(SWIGPYOUT) $(PYSITEDIR)/selinux/__init__.py

install-rubywrap: rubywrap
	test -d $(RUBYINSTALL) || install -m 755 -d $(RUBYINSTALL) 
	install -m 755 $(SWIGRUBYSO) $(RUBYINSTALL)/selinux.so

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean-pywrap:
	-rm -f $(SWIGLOBJ) $(SWIGSO) $(AUDIT2WHYLOBJ) $(AUDIT2WHYSO)

clean-rubywrap:
	-rm -f $(SWIGRUBYLOBJ) $(SWIGRUBYSO)

clean: clean-pywrap clean-rubywrap
	-rm -f $(LIBPC) $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) *.o *.lo *~

distclean: clean
	rm -f $(GENERATED) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

.PHONY: all clean clean-pywrap clean-rubywrap pywrap rubywrap swigify install install-pywrap install-rubywrap distclean
