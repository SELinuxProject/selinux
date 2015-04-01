# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCLUDEDIR ?= $(PREFIX)/include
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib
LIBEXECDIR ?= $(PREFIX)/libexec
HLLDIR ?= $(LIBEXECDIR)/selinux/hll

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -I$(INCLUDEDIR)
LDLIBS = -lsepol -L$(LIBDIR)

PP_SRCS = $(wildcard *.c)
PP_OBJS = $(patsubst %.c,%.o,$(PP_SRCS))

all: pp

pp: $(PP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

install: all
	-mkdir -p $(HLLDIR)
	install -m 755 pp $(HLLDIR)

relabel:

clean:
	-rm -f pp $(PP_OBJS)

indent:
	../../scripts/Lindent $(wildcard *.[ch])
