SUBDIRS = setfiles load_policy newrole run_init secon sestatus semodule setsebool scripts po man hll unsetfiles

PKG_CONFIG ?= pkg-config

LIBSELINUX_LDLIBS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):../libselinux/src" $(PKG_CONFIG) --libs libselinux)
LIBSEMANAGE_LDLIBS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):../libsemanage/src" $(PKG_CONFIG) --libs libsemanage)
export LIBSELINUX_LDLIBS LIBSEMANAGE_LDLIBS

all install relabel clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
