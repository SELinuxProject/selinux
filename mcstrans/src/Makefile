# Installation directories.
PREFIX ?= /usr
SBINDIR ?= /sbin
INITDIR ?= /etc/rc.d/init.d
SYSTEMDDIR ?= $(PREFIX)/lib/systemd

# If no specific libsepol.a is specified, fall back on LDFLAGS search path
# Otherwise, as $(LIBSEPOLA) already appears in the dependencies, there
# is no need to define a value for LDLIBS_LIBSEPOLA
ifeq ($(LIBSEPOLA),)
        LDLIBS_LIBSEPOLA := -l:libsepol.a
endif

PROG_SRC=mcstrans.c  mcscolor.c  mcstransd.c  mls_level.c
PROG_OBJS= $(patsubst %.c,%.o,$(PROG_SRC))
PROG=mcstransd
INITSCRIPT=mcstrans
CFLAGS ?= -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute

all: $(PROG)

$(PROG): $(PROG_OBJS) $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -pie -o $@ $^ -lselinux -lcap $(PCRE_LDLIBS) $(LDLIBS_LIBSEPOLA)

%.o:  %.c 
	$(CC) $(CFLAGS) $(PCRE_CFLAGS) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -fPIE -c -o $@ $<

install: all
	test -d $(DESTDIR)$(SBINDIR) || install -m 755 -d $(DESTDIR)$(SBINDIR)
	install -m 755 $(PROG) $(DESTDIR)$(SBINDIR)
	test -d $(DESTDIR)$(INITDIR) || install -m 755 -d $(DESTDIR)$(INITDIR)
	install -m 755 $(INITSCRIPT).init $(DESTDIR)$(INITDIR)/$(INITSCRIPT)
	test -d $(DESTDIR)$(SYSTEMDDIR)/system || install -m 755 -d $(DESTDIR)$(SYSTEMDDIR)/system
	install -m 644 mcstrans.service $(DESTDIR)$(SYSTEMDDIR)/system/

clean: 
	-rm -f $(OBJS) $(LOBJS) $(TARGET) $(PROG) $(PROG_OBJS) *~ \#*

