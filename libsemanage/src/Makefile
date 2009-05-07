# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYLIBVER ?= $(shell python -c 'import sys;print "python%d.%d" % sys.version_info[0:2]')
PYINC ?= /usr/include/${PYLIBVER}
PYLIBDIR ?= $(LIBDIR)/${PYLIBVER}
RUBYLIBVER ?= $(shell ruby -e 'print RUBY_VERSION.split(".")[0..1].join(".")')
RUBYPLATFORM ?= $(shell ruby -e 'print RUBY_PLATFORM')
RUBYINC ?= $(LIBDIR)/ruby/$(RUBYLIBVER)/$(RUBYPLATFORM)
RUBYINSTALL ?= $(LIBDIR)/ruby/site_ruby/$(RUBYLIBVER)/$(RUBYPLATFORM)

DEFAULT_SEMANAGE_CONF_LOCATION=$(DESTDIR)/etc/selinux/semanage.conf

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow -Werror
	export LDFLAGS = -g
endif

LEX = flex
LFLAGS = -s
YACC = bison
YFLAGS = -d

LIBVERSION = 1

LIBA=libsemanage.a
TARGET=libsemanage.so
SWIGIF= semanageswig_python.i
SWIGRUBYIF= semanageswig_ruby.i
SWIGCOUT= semanageswig_wrap.c
SWIGRUBYCOUT= semanageswig_ruby_wrap.c
SWIGLOBJ:= $(patsubst %.c,%.lo,$(SWIGCOUT)) 
SWIGRUBYLOBJ:= $(patsubst %.c,%.lo,$(SWIGRUBYCOUT)) 
SWIGSO=_semanage.so
SWIGFILES=$(SWIGSO) semanage.py 
SWIGRUBYSO=_rubysemanage.so
LIBSO=$(TARGET).$(LIBVERSION)

SWIGGEN=$(SWIGCOUT) $(SWIGRUBYCOUT)
SRCS= $(filter-out $(SWIGGEN),$(wildcard *.c))

OBJS= $(patsubst %.c,%.o,$(SRCS)) conf-scan.o conf-parse.o
LOBJS= $(patsubst %.c,%.lo,$(SRCS)) conf-scan.lo conf-parse.lo
CFLAGS ?= -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wmissing-format-attribute -Wno-unused-parameter

override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE 

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./

SWIGRUBY = swig -Wall -ruby -o $(SWIGRUBYCOUT) -outdir ./

GENERATED=$(SWIGCOUT) $(SWIGRUBYCOUT) $(wildcard conf-*.[ch])

all: $(LIBA) $(LIBSO) 

pywrap: all $(SWIGLOBJ) $(SWIGSO) 

rubywrap: all $(SWIGRUBYSO)

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(filter-out -Werror, $(CFLAGS)) -I$(PYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGRUBYLOBJ): $(SWIGRUBYCOUT)
	$(CC) $(filter-out -Werror,$(CFLAGS)) -I$(RUBYINC) -fPIC -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $< -L. -lsemanage -l$(PYLIBVER) -L$(LIBDIR) -Wl,-soname,$@,-z,defs

$(SWIGRUBYSO): $(SWIGRUBYLOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -L. -lsemanage -L$(LIBDIR) -Wl,-soname,$@

$(LIBA): $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -lsepol -lselinux -lbz2 -lustr -L$(LIBDIR) -Wl,-soname,$(LIBSO),--version-script=libsemanage.map,-z,defs
	ln -sf $@ $(TARGET)

conf-scan.c: conf-scan.l conf-parse.h
	$(LEX) $(LFLAGS) -t $< > $@

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
	$(SWIG) $^

$(SWIGRUBYCOUT): $(SWIGRUBYIF)
	$(SWIGRUBY) $^

swigify: $(SWIGIF)
	$(SWIG) $^

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	test -f $(DEFAULT_SEMANAGE_CONF_LOCATION) || install -m 644 -D semanage.conf $(DEFAULT_SEMANAGE_CONF_LOCATION)
	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

install-pywrap: pywrap 
	test -d $(PYLIBDIR)/site-packages || install -m 755 -d $(PYLIBDIR)/site-packages
	install -m 755 $(SWIGFILES) $(PYLIBDIR)/site-packages

install-rubywrap: rubywrap
	test -d $(RUBYINSTALL) || install -m 755 -d $(RUBYINSTALL) 
	install -m 755 $(SWIGRUBYSO) $(RUBYINSTALL)/semanage.so

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGSO) $(TARGET) conf-parse.c conf-parse.h conf-scan.c

distclean: clean
	rm -f $(SWIGCOUT) $(SWIGFILES)

indent:
	../../scripts/Lindent $(filter-out $(GENERATED),$(wildcard *.[ch]))

.PHONY: all clean pywrap rubywrap swigify install install-pywrap install-rubywrap distclean
