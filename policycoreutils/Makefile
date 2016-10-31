SUBDIRS = setfiles load_policy newrole run_init secon sestatus semodule_package semodule sepolgen-ifgen setsebool scripts po man hll

all install relabel clean indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
