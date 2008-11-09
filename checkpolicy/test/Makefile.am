noinst_PROGRAMS = $(c_extras)
c_extras = 
if BUILD_tests
c_extras  += dispol dismod
endif

dispol_LDADD	= $(LIBSEPOL_A_PATH)
dismod_LDADD	= $(LIBSEPOL_A_PATH)
AM_LDFLAGS	= -lselinux
