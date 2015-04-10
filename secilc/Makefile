PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

LDLIBS = -lsepol -L$(LIBDIR)
SECILC = secilc
SECILC_SRCS := secilc.c
SECILC_OBJS := $(patsubst %.c,%.o,$(SECILC_SRCS))

# The secilc man page:
MANPAGE = secilc.8
XMLTO = xmlto

CFLAGS ?= -Wall -Wshadow -Wextra -Wundef -Wmissing-format-attribute -Wcast-align -Wstrict-prototypes -Wpointer-arith -Wunused

override CFLAGS += -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

$(SECILC): $(SECILC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

all: $(SECILC) man

test: $(SECILC)
	./$(SECILC) test/policy.cil

man: $(MANPAGE).xml
	$(XMLTO) man $(MANPAGE).xml

install: all man
	-mkdir -p $(BINDIR)
	-mkdir -p $(MANDIR)/man8
	install -m 755 $(SECILC) $(BINDIR)
	install -m 644 $(MANPAGE) $(MANDIR)/man8

doc:
	$(MAKE) -C docs

clean:
	rm -f $(SECILC)
	rm -f $(SECILC_OBJS)
	rm -f policy.*
	rm -f file_contexts
	rm -f $(MANPAGE)

relabel:

.PHONY: all clean test install doc relabel
