if BUILD_run_init
AM_LDFLAGS		=  -Wl,--as-needed $(extra_ldflags)
extra_cppflags		= \
	-DUSE_NLS \
	-DLOCALEDIR="\"$(LOCALEDIR)\"" \
	-DPACKAGE="\"policycoreutils\""
extra_src		= 
extra_ldflags		=
sbin_PROGRAMS		= run_init open_init_pty
run_init_CPPFLAGS	= $(extra_cppflags)
man_MANS		= run_init.8 open_init_pty.8
if HAVE_PAM
extra_cppflags		+= -DUSE_PAM
extra_ldflags		+= -lpam -lpam_misc
pam_DATA		= run_init.pamd
else
extra_cppflags		+= -D_XOPEN_SOURCE=500
extra_ldflags		+= -lcrypt
endif
if have_libaudit
extra_cppflags		+= -DUSE_AUDIT
extra_ldflags		+= -laudit
endif
endif
