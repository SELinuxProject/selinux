bin_PROGRAMS		= restorecond

restorecond_SOURCES	= restorecond.c utmpwatcher.c stringslist.c
man_MANS		= restorecond.8
sysconf_DATA		= restorecond.conf 

AM_CPPFLAGS		= -D_FILE_OFFSET_BITS=64
AM_LDFLAGS		= -Wl,--as-needed

startup_SCRIPTS		= restorecond

startupdir		= $(STARTUP_DIR)

restorecond:restorecond.init
	cp $< $@
