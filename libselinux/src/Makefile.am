COMMONSRC = \
	compute_member.c get_default_type.c lgetfilecon.c selinux_config.c \
	compute_relabel.c getenforce.c load_policy.c \
	compute_user.c getfilecon.c lsetfilecon.c setenforce.c \
	context.c get_initial_context.c setfilecon.c \
	disable.c getpeercon.c matchmediacon.c setrans_client.c \
	callbacks.c enabled.c init.c matchpathcon.c seusers.c \
	canonicalize_context.c fgetfilecon.c is_customizable_type.c \
	policyvers.c freeconary.c label.c procattr.c check_context.c \
	freecon.c label_file.c query_user_context.c compute_av.c fsetfilecon.c \
	label_media.c compute_create.c get_context_list.c label_x.c \
	selinux_check_securetty_context.c

AVCSRC	= \
	avc.c avc_internal.c avc_sidtab.c \
	mapping.c stringrep.c checkAccess.c

BOOLSRC				= booleans.c
RPMSRC				= rpm.c
BUILDSRC			= $(COMMONSRC) 
AM_CFLAGS			= \
	-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	-I$(abs_top_srcdir)/include \
	$(extra_cflags)

extra_cflags			=
AM_LDFLAGS			= -Wl,--as-needed
SWIG_FLAGS			= -Wall -python -outdir $(srcdir)
lib_LTLIBRARIES			= libselinux.la
selinux_pyexecdir		= $(pyexecdir)/selinux
selinux_pythondir		= $(pythondir)/selinux
selinux_pyexec_LTLIBRARIES	= $(extra_lib)
selinux_python_PYTHON		= __init__.py

sysconf_DATA			= config
config:Makefile
	echo -e "SELINUXTYPE=$(policyname)\nSELINUX=enforcing" > $@ 
		
PACKAGE				= selinux
extra_lib			=
libselinux_la_SOURCES		= $(BUILDSRC)
libselinux_la_LDFLAGS		= -Wl,--as-needed -version-info 1
if enable_python
selinuxswig_wrap.c: Makefile selinuxswig.i selinuxswig_python.i
	$(SWIG) -o $@ $(SWIG_FLAGS) -interface libpyselinux $(srcdir)/selinuxswig_python.i 
extra_lib			+= libpyselinux.la
libpyselinux_la_SOURCES		= selinuxswig_wrap.c
libpyselinux_la_CPPFLAGS	= \
	-I@PYTHON_INCLUDE_DIR@
libpyselinux_la_LDFLAGS		= -Wl,--as-needed -lselinux -L$(builddir)
libpyselinux_la_DEPENDENCIES	= $(builddir)/libselinux.la
if have_sepol
extra_lib			+= libpyaudit2why.la
libpyaudit2why_la_SOURCES	= audit2why.c
libpyaudit2why_la_CPPFLAGS	= \
	-I@PYTHON_INCLUDE_DIR@
libpyaudit2why_la_DEPENDENCIES	= $(LIBSEPOL_A_PATH) $(builddir)/libselinux.la
libpyaudit2why_la_LDFLAGS	= -Wl,--as-needed -lselinux -L$(builddir) 
libpyaudit2why_la_LIBADD	= $(LIBSEPOL_A_PATH)
endif # have_sepol

endif # have python
if enable_avc
BUILDSRC += $(AVCSRC)
else
extra_cflags += -DDISABLE_AVC
endif
if enable_bool 
BUILDSRC += $(BOOLSRC)
else
extra_cflags += -DDISABLE_BOOL
endif
if enable_rpm
BUILDSRC += $(RPMSRC)
endif
