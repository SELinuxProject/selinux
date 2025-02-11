SUBDIRS = setfiles load_policy newrole run_init secon sestatus semodule setsebool scripts po man hll unsetfiles

PKG_CONFIG ?= pkg-config

LIBSELINUX_LDLIBS := $(shell $(PKG_CONFIG) --libs libselinux)
export LIBSELINUX_LDLIBS

all install relabel clean indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
