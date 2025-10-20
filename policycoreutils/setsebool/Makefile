# Installation directories.
LINGUAS ?=
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
BASHCOMPLETIONDIR ?= $(PREFIX)/share/bash-completion/completions

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I../../libselinux/include -I../../libsemanage/include
override LDFLAGS+= -L../../libselinux/src     -L../../libsemanage/src
override LDLIBS += $(LIBSEMANAGE_LDLIBS) $(LIBSELINUX_LDLIBS)
SETSEBOOL_OBJS = setsebool.o

BASHCOMPLETIONS=setsebool-bash-completion.sh 

all: setsebool

setsebool: $(SETSEBOOL_OBJS)

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 setsebool $(DESTDIR)$(SBINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 644 setsebool.8 $(DESTDIR)$(MANDIR)/man8/
	for lang in $(LINGUAS) ; do \
		if [ -e $${lang} ] ; then \
			mkdir -p $(DESTDIR)$(MANDIR)/$${lang}/man8 ; \
			install -m 644 $${lang}/*.8 $(DESTDIR)$(MANDIR)/$${lang}/man8/ ; \
		fi ; \
	done
	-mkdir -p $(DESTDIR)$(BASHCOMPLETIONDIR)
	install -m 644 $(BASHCOMPLETIONS) $(DESTDIR)$(BASHCOMPLETIONDIR)/setsebool

relabel:

clean:
	-rm -f setsebool *.o
