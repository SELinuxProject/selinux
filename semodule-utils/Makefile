SUBDIRS = semodule_package semodule_link semodule_expand semodule_deps

all install relabel clean indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
