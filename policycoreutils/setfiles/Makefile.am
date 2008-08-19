sbin_PROGRAMS		= setfiles
nodist_bin_SCRIPTS	= restorecon

restorecon: setfiles
	ln -sf setfiles restorecon

CLEANFILES		= restorecon

setfiles_SOURCES	= setfiles.c
man_MANS		= setfiles.8 restorecon.8
setfiles_CPPFLAGS	= $(libaudit_cppflags)
AM_LDFLAGS		=  -Wl,--as-needed 
libaudit_cppflags	= -D_FILE_OFFSET_BITS=64
if have_libaudit
libaudit_cppflags += -DUSE_AUDIT
endif
