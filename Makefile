SUBDIRS=libsepol libselinux libsemanage sepolgen checkpolicy secilc policycoreutils # policy
PYSUBDIRS=libselinux libsemanage
DISTCLEANSUBIDRS=libselinux libsemanage

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow -Werror
	export LDFLAGS = -g
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
