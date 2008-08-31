#only need selinux
# Enable capabilities to permit newrole to generate audit records.
# This will make newrole a setuid root program.
# The capabilities used are: CAP_AUDIT_WRITE.
AUDIT_LOG_PRIV		?= n
# Enable capabilities to permit newrole to utilitize the pam_namespace module.
# This will make newrole a setuid root program.
# The capabilities used are: CAP_SYS_ADMIN, CAP_CHOWN, CAP_FOWNER and
# CAP_DAC_OVERRIDE. 
NAMESPACE_PRIV		?= n
# If LSPP_PRIV is y, then newrole will be made into setuid root program.
# Enabling this option will force AUDIT_LOG_PRIV and NAMESPACE_PRIV to be y.
LSPP_PRIV		?= n

AM_LDFLAGS		=  -Wl,--as-needed $(extra_ldflags)
extra_cppflags		= \
	-DVERSION=\"$(VERSION)\"	\
	-DUSE_NLS 			\
	-DLOCALEDIR="\"$(LOCALEDIR)\""	\
	-DPACKAGE="\"policycoreutils\""
extra_src		= 
extra_ldflags		=
bin_PROGRAMS		= newrole
newrole_SOURCES		= newrole.c $(extra_src)
newrole_CPPFLAGS	= $(extra_cppflags)
man_MANS		= newrole.1

if HAVE_PAM
extra_cppflags		+= -DUSE_PAM
extra_src		+= hashtab.c
extra_ldflags		+= -lpam -lpam_misc
pam_DATA		= newrole
else
extra_cppflags		+= -D_XOPEN_SOURCE=500
extra_ldflags		+= -lcrypt
endif

if have_libaudit
extra_cppflags		+= -DUSE_AUDIT
extra_ldflags		+= -laudit
endif

