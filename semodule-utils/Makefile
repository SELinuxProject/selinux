SUBDIRS = semodule_package semodule_link semodule_expand

all install relabel clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
