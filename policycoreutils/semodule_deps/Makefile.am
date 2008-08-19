if BUILD_semodule_deps
bin_PROGRAMS			= semodule_deps
AM_LDFLAGS			= -Wl,--as-needed
semodule_deps_LDADD		= $(LIBSEPOL_A_PATH)
semodule_deps_DEPENDENCIES	= $(LIBSEPOL_A_PATH)
man_MANS			= semodule_deps.8
endif
