SUBDIRS = sepolicy setfiles semanage load_policy newrole run_init sandbox secon audit2allow sestatus semodule_package semodule semodule_link semodule_expand semodule_deps sepolgen-ifgen setsebool scripts po man gui hll

INOTIFYH = $(shell ls /usr/include/sys/inotify.h 2>/dev/null)

ifeq (${INOTIFYH}, /usr/include/sys/inotify.h)
	SUBDIRS += restorecond
endif

all install relabel clean indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
