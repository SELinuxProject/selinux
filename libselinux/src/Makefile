# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYLIBVER ?= $(shell python -c 'import sys;print "python%d.%d" % sys.version_info[0:2]')
PYINC ?= /usr/include/$(PYLIBVER)
PYLIB ?= /usr/lib/$(PYLIBVER)
PYTHONLIBDIR ?= $(LIBDIR)/$(PYLIBVER)

LIBVERSION = 1

LIBA=libselinux.a 
TARGET=libselinux.so
SWIGIF= selinuxswig_python.i
SWIGCOUT= selinuxswig_wrap.c
SWIGLOBJ:= $(patsubst %.c,%.lo,$(SWIGCOUT)) 
SWIGSO=_selinux.so
SWIGFILES=$(SWIGSO) selinux.py 
LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(filter-out $(SWIGCOUT),$(wildcard *.c))) 
LOBJS= $(patsubst %.c,%.lo,$(filter-out $(SWIGCOUT),$(wildcard *.c)))
CFLAGS ?= -Werror -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
RANLIB=ranlib

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
TLSFLAGS += -mno-tls-direct-seg-refs
endif

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./

GENERATED=$(SWIGCOUT)

all: $(LIBA) $(LIBSO) 

pywrap: all $(SWIGSO)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(filter-out -Werror,$(CFLAGS)) -I$(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $< -L. -lselinux -L$(LIBDIR) -Wl,-soname,$@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -ldl -lsepol -L$(LIBDIR) -Wl,-soname,$(LIBSO),-z,defs,-z,relro
	ln -sf $@ $(TARGET) 

%.o:  %.c policy.h
	$(CC) $(CFLAGS) $(TLSFLAGS) -c -o $@ $<

%.lo:  %.c policy.h
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

$(SWIGCOUT): $(SWIGIF)
	$(SWIG) $^

swigify: $(SWIGIF)
	$(SWIG) $^

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

install-pywrap: pywrap
	test -d $(PYTHONLIBDIR)/site-packages || install -m 755 -d $(PYTHONLIBDIR)/site-packages
	install -m 755 $(SWIGFILES) $(PYTHONLIBDIR)/site-packages

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGSO) $(TARGET) 

distclean: clean
	rm -f $(SWIGCOUT) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

