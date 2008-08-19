bin_PROGRAMS	= chkcon
AM_LDFLAGS	= -Wl,--as-needed
AM_CPPFLAGS	= -I$(abs_top_srcdir)/include
chkcon_SOURCES	= chkcon.c
chkcon_DEPENDENCIES	= $(builddir)/../src/libsepol.la
chkcon_LDFLAGS	= -lsepol -L$(builddir)/../src
