PYTHON ?= python3
SECILC ?= secilc

# Installation directories.
LINGUAS ?= ru
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

CFLAGS ?= -Werror -Wall -W

# If no specific libsepol.a is specified, fall back on LDFLAGS search path
# Otherwise, as $(LIBSEPOLA) already appears in the dependencies, there
# is no need to define a value for LDLIBS_LIBSEPOLA
ifeq ($(LIBSEPOLA),)
        LDLIBS_LIBSEPOLA := -l:libsepol.a
endif

all: audit2why sepolgen-ifgen-attr-helper

sepolgen-ifgen-attr-helper: sepolgen-ifgen-attr-helper.o $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS_LIBSEPOLA) -lselinux

audit2why:
	ln -sf audit2allow audit2why

test: all test_dummy_policy
	@$(PYTHON) test_audit2allow.py -v

test_dummy_policy: test_dummy_policy.cil
	$(SECILC) -o $@ -f /dev/null $<

install: all
	-mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 audit2allow $(DESTDIR)$(BINDIR)
	(cd $(DESTDIR)$(BINDIR); ln -sf audit2allow audit2why)
	install -m 755 sepolgen-ifgen-attr-helper $(DESTDIR)$(BINDIR)
	install -m 755 sepolgen-ifgen $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man1
	install -m 644 audit2allow.1 $(DESTDIR)$(MANDIR)/man1/
	install -m 644 audit2why.1 $(DESTDIR)$(MANDIR)/man1/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man1 ; \
			install -m 644 $${lang}/*.1 $(DESTDIR)$(MANDIR)/$${lang}/man1/ ; \
		fi ; \
	done

clean:
	rm -f *~ *.o sepolgen-ifgen-attr-helper test_dummy_policy

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel: ;
