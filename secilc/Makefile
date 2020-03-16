PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

SECILC = secilc
SECILC_SRCS := secilc.c
SECILC_OBJS := $(patsubst %.c,%.o,$(SECILC_SRCS))

SECIL2CONF = secil2conf
SECIL2CONF_SRCS := secil2conf.c
SECIL2CONF_OBJS := $(patsubst %.c,%.o,$(SECIL2CONF_SRCS))

SECILC_MANPAGE = secilc.8
SECIL2CONF_MANPAGE = secil2conf.8
XMLTO = xmlto
DIFF = diff

CHECKPOLICY = checkpolicy
POL_VERS = $(shell $(CHECKPOLICY) -V | cut -f 1 -d ' ')

CFLAGS ?= -Wall -Wshadow -Wextra -Wundef -Wmissing-format-attribute -Wcast-align -Wstrict-prototypes -Wpointer-arith -Wunused

override CFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
override LDLIBS += -lsepol

all: $(SECILC) $(SECIL2CONF) man

$(SECILC): $(SECILC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(SECILC)
	./$(SECILC) test/policy.cil
	./$(SECILC) -c $(POL_VERS) -O -M 1 -f /dev/null -o opt-actual.bin test/opt-input.cil
	$(CHECKPOLICY) -b -C -M -o opt-actual.cil opt-actual.bin >/dev/null
	$(DIFF) test/opt-expected.cil opt-actual.cil

$(SECIL2CONF): $(SECIL2CONF_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

man: $(SECILC_MANPAGE) $(SECIL2CONF_MANPAGE)

$(SECILC_MANPAGE): $(SECILC_MANPAGE).xml
	$(XMLTO) man $(SECILC_MANPAGE).xml

$(SECIL2CONF_MANPAGE): $(SECIL2CONF_MANPAGE).xml
	$(XMLTO) man $(SECIL2CONF_MANPAGE).xml

install: all man
	-mkdir -p $(DESTDIR)$(BINDIR)
	-mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 755 $(SECILC) $(DESTDIR)$(BINDIR)
	install -m 755 $(SECIL2CONF) $(DESTDIR)$(BINDIR)
	install -m 644 $(SECILC_MANPAGE) $(DESTDIR)$(MANDIR)/man8
	install -m 644 $(SECIL2CONF_MANPAGE) $(DESTDIR)$(MANDIR)/man8

doc:
	$(MAKE) -C docs

clean:
	rm -f $(SECILC)
	rm -f $(SECILC_OBJS)
	rm -f $(SECIL2CONF)
	rm -f $(SECIL2CONF_OBJS)
	rm -f policy.*
	rm -f file_contexts
	rm -f $(SECILC_MANPAGE)
	rm -f $(SECIL2CONF_MANPAGE)
	rm -f opt-actual.cil
	rm -f opt-actual.bin
	$(MAKE) -C docs clean

relabel:

.PHONY: all clean test install doc relabel man
