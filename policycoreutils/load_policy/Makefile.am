custom_cppflags		= \
	-DUSE_NLS \
	-DLOCALEDIR="\"$(localedir)\"" \
	-DPACKAGE="\"policycoreutils\""
sbin_PROGRAMS		= load_policy
man_MANS		= load_policy.8
load_policy_CPPFLAGS	= $(custom_cppflags)
AM_LDFLAGS		=  -Wl,--as-needed 
