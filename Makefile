SUBDIRS=libsepol libselinux libsemanage checkpolicy policycoreutils # policy
PYSUBDIRS=libselinux libsemanage

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow 
	export LDFLAGS = -g
endif

install relabel:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-pywrap:
	@for subdir in $(PYSUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

distclean:
	@for subdir in libselinux libsemanage; do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
