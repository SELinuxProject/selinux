#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libsepol], [1] BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([utils/chkcon.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
# semodule_deps in policycoreutils builds against libsepol.a
# Uncomment to change default behavior
#AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AM_PROG_CC_C_O



# Checks for libraries.
AC_CHECK_LIB([fl], [yywrap])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h \
	limits.h \
	netinet/in.h \
	stddef.h \
	stdint.h \
	stdio_ext.h \
	stdlib.h \
	string.h \
	sys/socket.h \
	unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strcasecmp strchr strdup strerror strncasecmp strrchr])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 man/Makefile
                 src/Makefile
                 utils/Makefile])
AC_OUTPUT

PRINT='echo -n -e '
$PRINT "\n*** Libsepol Configuration Summary ***\n"
$PRINT "\tBuilding static lib\t= $enable_static\n"
$PRINT "\tBuilding shared object\t= $enable_shared\n"
$PRINT "------------------------------------------------------------\n" 

