noinst_PROGRAMS = $(c_extra)
if BUILD_tests
c_extra	= libsemanage-tests
else
c_extra	=
endif
libsemanage_tests_SOURCES	= libsemanage-tests.c test_semanage_store.c \
				test_utilities.c utilities.c

libsemanage_tests_CFLAGS	=  -I$(top_srcdir) -I$(top_srcdir)/include/semanage
libsemanage_tests_LDFLAGS	=  -Wl,--as-needed
