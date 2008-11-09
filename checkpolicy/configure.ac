#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([checkpolicy], VERSION, selinux@tycho.nsa.gov)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([module_compiler.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_YACC
if test -z "$ac_cv_prog_YACC" ; then
	AC_MSG_ERROR([Could not find yacc])
fi

AM_PROG_LEX
if test -z "$ac_cv_prog_LEX" ; then
	AC_MSG_ERROR([Could not find lex])
fi
AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_PROGS(NM, nm, [])

# Checks for libraries.
AC_CHECK_LIB([fl], [yywrap])

if test -z "$NM" ; then
	AC_MSG_WARN([Cannot test libsepol.a])
fi
# As of testing (May 2008) this test fails because this function is hidden in the .so
# due to the visibility discrepency between the .a and the .so this test was just kept
# for any future modifcations to this file to be made faster/easier.
#AC_SEARCH_LIBS([sepol_set_policydb],[sepol],
#		[],
#		[AC_MSG_NOTICE([********************************************************])]
#		[AC_MSG_ERROR([[SELinux Policy library was not found. Aborted]])],
#		[]
#)

# TODO: Write a proper conftest test for this library
AC_ARG_WITH([static-libsepol],
	[AC_HELP_STRING([--with-static-libsepol=PATH],
		[libsepol.a library to build against. Manadatory])],
	[AC_MSG_CHECKING([for libsepol.a ])]
	[if @<:@ -f "$with_static_libsepol/libsepol.a" @:>@ ; then
			AC_MSG_RESULT([$with_static_libsepol/libsepol.a found])
			if ! nm "$with_static_libsepol/libsepol.a" 2>&1 | grep -q sepol_polcap_getnum ; then
				AC_MSG_ERROR([libsepol.a not compatible])
			fi
			AC_SUBST([LIBSEPOL_A_PATH], [[$with_static_libsepol/libsepol.a]])
	elif @<:@ -f "$with_static_libsepol" @:>@ ; then
			AC_MSG_RESULT([$with_static_libsepol ok])
			if ! nm "$with_static_libsepol" 2>&1 | grep -q sepol_polcap_getnum ; then
				AC_MSG_ERROR([libsepol.a not compatible])
			fi
			AC_SUBST([LIBSEPOL_A_PATH], [[$with_static_libsepol]])
	else
		AC_MSG_RESULT([no found])
		AC_MSG_ERROR([[Provide path to libsepol.a --with-static-libsepol=PATH]])
		
	fi], 
	[AC_MSG_CHECKING([for libsepol.a in $libdir])]
	[if @<:@ -f "$prefix/lib/libsepol.a" @:>@ ; then
		AC_MSG_RESULT([$prefix/lib/libsepol.a found])
		if ! nm "$prefix/lib/libsepol.a" 2>&1 | grep -q sepol_polcap_getnum ; then
			AC_MSG_ERROR([libsepol.a not compatible. Try --with-static-libsepol=PATH])
		fi
                AC_SUBST([LIBSEPOL_A_PATH], [[$prefix/lib/libsepol.a]])
	elif @<:@ -f "$libdir/libsepol.a" @:>@ ; then
		AC_MSG_RESULT([$libdir/libsepol.a found])
		if ! nm "$libdir/libsepol.a" 2>&1 | grep -q sepol_polcap_getnum ; then
			AC_MSG_ERROR([libsepol.a not compatible. Try --with-static-libsepol=PATH])
		fi
                AC_SUBST([LIBSEPOL_A_PATH], [[$libdir/libsepol.a]])
	else
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([[Provide path to libsepol.a. use --with-static-libsepol=PATH]])
	fi]
)

AC_ARG_ENABLE([tests],
	[AC_HELP_STRING([--enable-tests],[Enables building of tests])],
	[enable_tests=$enableval],
	[enable_tests=no]
)

AM_CONDITIONAL([BUILD_tests],[test "$enable_tests" = "yes"])
		
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h \
		netinet/in.h stdint.h stdlib.h \
		string.h sys/socket.h unistd.h])

#NOTE: A more proficient test is needed for libsepol's headers
AC_CHECK_HEADERS([sepol/policydb/policydb.h \
		sepol/policydb/avrule_block.h \
		sepol/policydb/conditional.h \
		sepol/policydb/hashtab.h],
		[],
		[AC_MSG_ERROR([Could not find sepol development headers])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strcasecmp strchr strdup strerror strtol strtoul])

AC_CONFIG_FILES([Makefile test/Makefile])

# Pickup the version info from the source directory if available
VERSION=`cat $srcdir/VERSION`
if test "$VERSION" = "" ; then
        VERSION=git
fi

AC_OUTPUT

PRINT='echo -n -e '

$PRINT "\nCheckpolicy/module Configuration Summary:\n"
$PRINT "\tBuild Tests\t= $enable_tests\n"
$PRINT "\tcheckpolicy\t= yes\n"
$PRINT "\tchecknodule\t= yes\n"
$PRINT "\tlibsepol.a\t= $LIBSEPOL_A_PATH\n"
$PRINT "------------------------------------------------------------\n"
