COMMONSRC		= assertion.c conditional.c ebitmap.c hashtab.c \
			mls.c policydb.c roles.c users.c \
			avrule_block.c constraint.c expand.c hierarchy.c \
			module.c policydb_convert.c services.c util.c \
			avtab.c context.c genbools.c iface_record.c \
			node_record.c  policydb_public.c sidtab.c write.c \
			boolean_record.c context_record.c genusers.c \
			interfaces.c nodes.c port_record.c symtab.c \
			booleans.c debug.c handle.c link.c polcaps.c \
			ports.c user_record.c av_permissions.h \
			boolean_internal.h context.h context_internal.h \
			debug.h dso.h handle.h iface_internal.h mls.h \
			module_internal.h node_internal.h policydb_internal.h \
			port_internal.h private.h user_internal.h

lib_LTLIBRARIES		= libsepol.la
libsepol_la_SOURCES	= $(COMMONSRC)
libsepol_la_CPPFLAGS	= \
	-D_GNU_SOURCE -fPIC \
	-I$(abs_top_srcdir)/include
libsepol_la_LDFLAGS	= -version-info 1
AM_LDFLAGS		= -Wl,--as-needed
