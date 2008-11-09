COMMON = avcstat getenforce  getseuser selinuxenabled \
	compute_user getfilecon matchpathcon setenforce \
	getconlist getpidcon policyvers setfilecon \
	getdefaultcon selinux_check_securetty_context

BUILDS = $(COMMON)

AVC	= compute_av compute_create compute_member compute_relabel
BOOL	= getsebool togglesebool

if enable_avc
BUILDS += $(AVC)
endif
if enable_bool 
BUILDS += $(BOOL)
endif

bin_PROGRAMS	= $(BUILDS)
AM_LDFLAGS	= -Wl,--as-needed -lselinux -L$(top_builddir)/src
AM_CPPFLAGS	= -I$(top_srcdir)/include
BUILT_SOURCES	= $(top_builddir)/src/libselinux.la
