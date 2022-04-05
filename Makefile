PREFIX ?= /usr
OPT_SUBDIRS ?= dbus gui mcstrans python restorecond sandbox semodule-utils
SUBDIRS=libsepol libselinux libsemanage checkpolicy secilc policycoreutils $(OPT_SUBDIRS)
PYSUBDIRS=libselinux libsemanage
DISTCLEANSUBDIRS=libselinux libsemanage

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow -Werror
	export LDFLAGS = -g
else
	export CFLAGS ?= -O2 -Werror -Wall -Wextra \
		-Wfloat-equal \
		-Wformat=2 \
		-Winit-self \
		-Wmissing-format-attribute \
		-Wmissing-noreturn \
		-Wmissing-prototypes \
		-Wnull-dereference \
		-Wpointer-arith \
		-Wshadow \
		-Wstrict-prototypes \
		-Wundef \
		-Wunused \
		-Wwrite-strings \
		-fno-common
endif

ifneq ($(DESTDIR),)
	LIBDIR ?= $(DESTDIR)$(PREFIX)/lib
	LIBSEPOLA ?= $(LIBDIR)/libsepol.a

	CFLAGS += -I$(DESTDIR)$(PREFIX)/include
	LDFLAGS += -L$(DESTDIR)$(PREFIX)/lib -L$(LIBDIR)
	export CFLAGS
	export LDFLAGS
	export LIBSEPOLA
endif

all install relabel clean test indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-pywrap install-rubywrap swigify:
	@for subdir in $(PYSUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

distclean:
	@for subdir in $(DISTCLEANSUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
