#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libsemanage, 2.0.28, selinux@tycho.nsa.gov)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/modules.c])
AC_CONFIG_HEADER([config.h])


# Checks for programs.
AC_PROG_YACC
if test -z "$ac_cv_prog_YACC" ; then
	AC_MSG_ERROR([Could not find yacc])
fi
AC_PROG_CC
AC_PROG_LEX
if test -z "$ac_cv_prog_LEX" ; then
	AC_MSG_ERROR([Could not find lex])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
# Static lib is used to build checkpolicy/module
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AM_PATH_PYTHON
AC_PATH_PROGS([SWIG],[swig])

AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([selinux],[selinux_init_load_policy],
	[],
	[AC_MSG_ERROR([[SELinux library was not found.]])]
)
AC_CHECK_LIB([sepol],[sepol_policydb_read],
	[],
	[AC_MSG_ERROR([[SELinux Policy library was not found.]])]
)

AC_CHECK_LIB([ustr],[ustr_free],
	[],
	[AC_MSG_ERROR([[ustr Micro String library was not found.]])]
)
	
# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h float.h limits.h \
	stddef.h stdio_ext.h stdlib.h \
	string.h strings.h sys/file.h \
	sys/time.h unistd.h])

AC_CHECK_HEADER([selinux/selinux.h],
	[],
	[AC_MSG_ERROR([[SELinux headers are missing.]])]
)

AC_CHECK_HEADER([ustr.h],
	[AC_DEFINE(HAVE_USTR_H, 1, [Define to 1 if you have <ustr.h>.])]
	,
        [AC_MSG_ERROR([[ustr Micro String library header is missing.]])]
)

AC_ARG_WITH([pythonver],
	[AC_HELP_STRING([--with-pythonver=x],[Python version (eg 2.4) ])],
        [],
        [with_pythonver=$PYTHON_VERSION]
)

AC_ARG_WITH([python],
        [AC_HELP_STRING([--with-python=PATH],[Optional path to python includedir 
		(eg prefix/include/python2.4)for python clients])],
        [],
        [with_python=no]
)

AC_ARG_WITH([python-site],
        [AC_HELP_STRING([--with-python-site=PATH],
                        [Optional path to python site-packages folder,
                        eg /usr/lib/python2.4/site-packages])],
        []
)

AC_ARG_ENABLE([swig],
	[AC_HELP_STRING([--disable-swig],
		[Disable regeneration of python c interface (default=no)])],
	[_enable_swig=$enableval],
	[_enable_swig=yes]
)

AC_ARG_ENABLE([tests],
        [AC_HELP_STRING([--disable-tests],[Disable building tests])],
        [enable_tests=$enableval],
        [enable_tests=no]
)

AM_CONDITIONAL([BUILD_tests],[test "$enable_tests" = "yes"])

if test "$enable_tests" = "yes" ; then
	AC_CHECK_LIB([cunit],[CU_initialize_registry],
		[],
		[AC_MSG_ERROR([CUnit is needed to build tests. Install cunit or --disable-tests])]
	)
fi
if test "$with_python" != "no" ; then
        AC_SUBST([PYTHON_INCLUDE_DIR],[$with_python])

        if test -d "$with_python" -a  -f "$with_python/Python.h"; then
		AC_SEARCH_LIBS([PyObject_Init],[python$with_pythonver],
			[have_python=yes],
			[have_python=no]
			[AC_MSG_WARN([
			[python$with_pythonver library could not be found. 
				Cannot build libpysemanage]])]
		)
	fi
fi

AM_CONDITIONAL([enable_python], [test "$have_python" = yes])

# Hault the config if we are asked for swig, but not swig is found
if test "$_enable_swig" = "yes" -a -z "$SWIG" ; then
        AC_MSG_ERROR([Cannot find swig interface gemerator in PATH,
                Disable python c-inteferace regeneration with --disable-swig])
fi

# If libpy*.so wrapper cannot be built, then do not rebuild swig interface
# even if swig is available, and do not install site-packages
if test "$have_python" != "yes" ; then
        _enable_swig=no
        AC_MSG_NOTICE([Swig interface does not need to be regenerated
                because libpyselinux.so wrapper cannot be built])
else
        # Use what the user specified, otherwise fallback on autoconf
        # internal default and display warning to user.
        # autoconf default = libdir/pythonX.X/site-packages
        if test -n "$with_python_site" ; then
                AC_SUBST([pythondir],[$with_python_site])
                AC_SUBST([pyexecdir],[$with_python_site])
        else
                AC_MSG_WARN([Python site folder not specified, guessing...])
        fi
fi


# slip in fake swig if needed
if test "$_enable_swig" != "yes" ; then
        AC_SUBST([SWIG],[/bin/true])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_FUNC_FORK
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([endpwent floor memset \
	mkdir munmap regcomp rmdir \
	select strcasecmp strchr \
	strdup strerror strndup \
	strrchr strstr strtol \
	strtoul strverscmp])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 include/Makefile
		 tests/Makefile
                 man/Makefile])

AC_OUTPUT

PRINT='echo -n -e '
$PRINT  "\nLibsemanage Configuration Summary:\n"
if test "$have_python" = "yes" ; then
	$PRINT "\tlibpysemanage.so\t= $have_python (Using $with_python) \n"
	$PRINT "\tPython Packages folder\t= $pythondir\n"
else
	$PRINT "\tlibpysemanage.so\t= no "
	$PRINT "(try --with-python=/usr/include/python$PYTHON_VERSION) \n"
fi
$PRINT "\tRegenerate py wrapper\t= $_enable_swig\n"
$PRINT "\tBuilding static lib\t= $enable_static\n"
$PRINT "\tBuilding shared object\t= $enable_shared\n"
$PRINT "\tBuilding tests\t\t= $enable_tests\n"
$PRINT "------------------------------------------------------------\n"
