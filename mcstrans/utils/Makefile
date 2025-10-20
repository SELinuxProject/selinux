# Installation directories.
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin

override CFLAGS += -I../../libselinux/include
override LDFLAGS+= -L../../libselinux/src

TARGETS=transcon untranscon

# If no specific libsepol.a is specified, fall back on LDFLAGS search path
# Otherwise, as $(LIBSEPOLA) already appears in the dependencies, there
# is no need to define a value for LDLIBS_LIBSEPOLA
ifeq ($(LIBSEPOLA),)
        LDLIBS_LIBSEPOLA := -l:libsepol.a
endif

all: $(TARGETS)

transcon: transcon.o ../src/mcstrans.o ../src/mls_level.o $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -o $@ $^ $(PCRE_LDLIBS) -lselinux $(LDLIBS_LIBSEPOLA)

untranscon: untranscon.o ../src/mcstrans.o ../src/mls_level.o $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -o $@ $^ $(PCRE_LDLIBS) -lselinux $(LDLIBS_LIBSEPOLA)

%.o:  %.c 
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PCRE_CFLAGS) -D_GNU_SOURCE -I../src -fPIE -c -o $@ $<

install: all
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 $(TARGETS) $(DESTDIR)$(SBINDIR)

test:
	./mlstrans-test-runner.py ../test/*.test

clean:
	rm -f $(TARGETS) *.o *~ \#*

relabel:
