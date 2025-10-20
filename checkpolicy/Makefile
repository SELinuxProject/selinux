#
# Makefile for building the checkpolicy program
#
LINGUAS ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
TARGETS = checkpolicy checkmodule

LEX = flex
YACC = bison -y

CFLAGS ?= -g -Wall -Werror -Wshadow -O2 -fno-strict-aliasing

# If no specific libsepol.a is specified, fall back on LDFLAGS search path
# Otherwise, as $(LIBSEPOLA) already appears in the dependencies, there
# is no need to define a value for LDLIBS_LIBSEPOLA
ifeq ($(LIBSEPOLA),)
        LDLIBS_LIBSEPOLA := -l:libsepol.a
endif

CHECKOBJS = y.tab.o lex.yy.o queue.o module_compiler.o parse_util.o \
	    policy_define.o
CHECKPOLOBJS = $(CHECKOBJS) checkpolicy.o
CHECKMODOBJS = $(CHECKOBJS) checkmodule.o

GENERATED=lex.yy.c y.tab.c y.tab.h

all:  $(TARGETS)
	$(MAKE) -C test

checkpolicy: $(CHECKPOLOBJS) $(LIBSEPOLA)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS_LIBSEPOLA)

checkmodule: $(CHECKMODOBJS) $(LIBSEPOLA)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS_LIBSEPOLA)

%.o: %.c 
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

y.tab.o: y.tab.c
	$(CC) $(filter-out -Werror, $(CPPFLAGS) $(CFLAGS)) -o $@ -c $<

lex.yy.o: lex.yy.c
	$(CC) $(filter-out -Werror, $(CPPFLAGS) $(CFLAGS)) -o $@ -c $<

y.tab.c: policy_parse.y
	$(YACC) -d policy_parse.y

lex.yy.c: policy_scan.l y.tab.c
	$(LEX) policy_scan.l

.PHONY: test
test: checkpolicy
	./tests/test_roundtrip.sh

# helper target for fuzzing
checkobjects: $(CHECKOBJS)

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 755 $(TARGETS) $(DESTDIR)$(BINDIR)	
	install -m 644 checkpolicy.8 $(DESTDIR)$(MANDIR)/man8
	install -m 644 checkmodule.8 $(DESTDIR)$(MANDIR)/man8
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
		fi ; \
	done

relabel: install
	/sbin/restorecon $(DESTDIR)$(BINDIR)/checkpolicy
	/sbin/restorecon $(DESTDIR)$(BINDIR)/checkmodule

clean:
	-rm -f $(TARGETS) $(CHECKPOLOBJS) $(CHECKMODOBJS) y.tab.c y.tab.h lex.yy.c tests/testpol.conf tests/testpol.bin
	$(MAKE) -C test clean
