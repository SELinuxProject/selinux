# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
USRBINDIR ?= $(PREFIX)/sbin
SBINDIR ?= $(DESTDIR)/sbin

MAX_STACK_SIZE=8192
CFLAGS ?= -O -Wall -W -Wundef -Wformat-y2k -Wformat-security -Winit-self -Wmissing-include-dirs \
          -Wunused -Wunknown-pragmas -Wstrict-aliasing -Wshadow -Wpointer-arith \
          -Wbad-function-cast -Wcast-align -Wwrite-strings -Wlogical-op -Waggregate-return \
          -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
          -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute \
          -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wvolatile-register-var \
          -Wdisabled-optimization -Wbuiltin-macro-redefined -Wpacked-bitfield-compat \
          -Wsync-nand -Wattributes -Wcoverage-mismatch -Wmultichar -Wcpp \
          -Wdeprecated-declarations -Wdiv-by-zero -Wdouble-promotion -Wendif-labels -Wextra \
          -Wformat-contains-nul -Wformat-extra-args -Wformat-zero-length -Wformat=2 -Wmultichar \
          -Wnormalized=nfc -Woverflow -Wpointer-to-int-cast -Wpragmas -Wsuggest-attribute=const \
          -Wsuggest-attribute=noreturn -Wsuggest-attribute=pure -Wtrampolines \
          -Wno-missing-field-initializers -Wno-sign-compare -Wjump-misses-init \
          -Wno-format-nonliteral -Wframe-larger-than=$(MAX_STACK_SIZE) -Wp,-D_FORTIFY_SOURCE=2 \
          -fstack-protector-all --param=ssp-buffer-size=4 -fexceptions \
          -fasynchronous-unwind-tables -fdiagnostics-show-option -funit-at-a-time \
          -fipa-pure-const -Wno-suggest-attribute=pure -Wno-suggest-attribute=const \
          -Werror -Wno-aggregate-return -Wno-redundant-decls
override CFLAGS += -I../include -D_GNU_SOURCE $(EMFLAGS)
LDLIBS += -L../src -lselinux -L$(LIBDIR)

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

sefcontext_compile: LDLIBS += -lpcre

ifeq ($(DISABLE_AVC),y)
	UNUSED_TARGETS+=compute_av compute_create compute_member compute_relabel
endif
ifeq ($(DISABLE_BOOL),y)
	UNUSED_TARGETS+=getsebool togglesebool
endif
TARGETS:= $(filter-out $(UNUSED_TARGETS), $(TARGETS))

all: $(TARGETS)

install: all
	-mkdir -p $(USRBINDIR)
	install -m 755 $(TARGETS) $(USRBINDIR)
	-mkdir -p $(SBINDIR)
clean:
	rm -f $(TARGETS) *.o *~

distclean: clean

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:

