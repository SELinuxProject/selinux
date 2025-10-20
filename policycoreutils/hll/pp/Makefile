# Installation directories.
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
HLLDIR ?= $(LIBEXECDIR)/selinux/hll

CFLAGS ?= -Werror -Wall -W
override LDLIBS += -lsepol

PP_SRCS = $(sort $(wildcard *.c))
PP_OBJS = $(patsubst %.c,%.o,$(PP_SRCS))

all: pp

pp: $(PP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

install: all
	-mkdir -p $(DESTDIR)$(HLLDIR)
	install -m 755 pp $(DESTDIR)$(HLLDIR)

relabel:

clean:
	-rm -f pp $(PP_OBJS)
