# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(DESTDIR)/sbin
INITDIR ?= $(DESTDIR)/etc/rc.d/init.d
SYSTEMDDIR ?= $(DESTDIR)/usr/lib/systemd
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

PROG_SRC=mcstrans.c  mcscolor.c  mcstransd.c  mls_level.c
PROG_OBJS= $(patsubst %.c,%.o,$(PROG_SRC))
PROG=mcstransd
INITSCRIPT=mcstrans
CFLAGS ?= -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

all: $(PROG)

$(PROG): $(PROG_OBJS)
	$(CC) $(LDFLAGS) -pie -o $@ $^ -lselinux -lcap -lpcre $(LIBSEPOLA)

%.o:  %.c 
	$(CC) $(CFLAGS) -fPIE -c -o $@ $<

install: all
	test -d $(SBINDIR) || install -m 755 -d $(SBINDIR)
	install -m 755 $(PROG) $(SBINDIR)
	test -d $(INITDIR) || install -m 755 -d $(INITDIR)
	install -m 755 $(INITSCRIPT).init $(INITDIR)/$(INITSCRIPT)
	test -d $(SYSTEMDDIR)/system || install -m 755 -d $(SYSTEMDDIR)/system
	install -m 644 mcstrans.service $(SYSTEMDDIR)/system/

clean: 
	-rm -f $(OBJS) $(LOBJS) $(TARGET) $(PROG) $(PROG_OBJS) *~ \#*

