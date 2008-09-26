#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libselinux], [VERSION], BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([utils/compute_create.c])
AC_CONFIG_HEADER([config.h])

AM_PATH_PYTHON

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

AC_PROG_LIBTOOL

AC_PATH_PROGS([SWIG],[swig])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS( \
	[fcntl.h 	float.h 	limits.h \
	netdb.h		stddef.h 	stdint.h \
	stdio_ext.h	stdlib.h 	string.h \
	strings.h 	sys/ioctl.h 	sys/mount.h \
	sys/socket.h 	sys/vfs.h 	syslog.h \
	unistd.h])

AC_CHECK_HEADERS([sepol/sepol.h sepol/policydb.h],[],
	[AC_MSG_ERROR([Cannot find sepol headers])])
	

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([floor	mempcpy		memset 	\
	munmap 		regcomp		socket	\	
	stpcpy 		strcasecmp	strchr	\	
	strdup 		strerror	strncasecmp	\
	strstr 		strtol		strtoul		\
	strverscmp	uname])


AC_ARG_ENABLE([rpm],
	[AC_HELP_STRING([--disable-rpm],[Disables rpm support (default=no)])],
	[_enable_rpm=$enableval],
	[_enable_rpm=yes])

AC_ARG_ENABLE([avc],
	[AC_HELP_STRING([--disable-avc],[Disables avc support (default=no)])],
	[_enable_avc=$enableval],
	[_enable_avc=yes])

AC_ARG_ENABLE([bool],
	[AC_HELP_STRING([--disable-bool],[Disables boolean support (default=no)])],
	[_enable_bool=$enableval],
	[_enable_bool=yes])

AC_ARG_ENABLE([docs],
	[AC_HELP_STRING([--disable-docs],
		[Disables installation of man pages (defualt=no)])],
	[_enable_docs=$enableval],
	[_enable_docs=yes])

AM_CONDITIONAL([enable_rpm], [ test "$_enable_rpm" = yes])
AM_CONDITIONAL([enable_avc], [ test "$_enable_avc" = yes])
AM_CONDITIONAL([enable_bool], [ test "$_enable_bool" = yes])
AM_CONDITIONAL([enable_docs], [ test "$_enable_docs" = yes])

AC_ARG_WITH([python-site],
	[AC_HELP_STRING([--with-python-site=PATH],
			[Optional path to python site-packages folder,
			eg /usr/lib/python2.4/site-packages])],
	[]
)

if test -n "$with_python_site" ; then
	AC_SUBST([pythondir],[$with_python_site])
	AC_SUBST([pyexecdir],[$with_python_site])
else
	AC_MSG_WARN([Python site folder not specified, guessing...])
fi

AC_ARG_WITH([python],
	[AC_HELP_STRING(
		[--with-python=PATH],
		[ Optional path to python includedir 
		  (eg prefix/include/python2.4)for python clients])],
	[],
	[with_python=no]
)
if test "$with_python" != "no" ; then
	AC_SUBST([PYTHON_INCLUDE_DIR],[$with_python])
	if test -d "$with_python" -a  -f "$with_python/Python.h"; then 
		have_python=yes;
	else
		have_python=no;
	fi

fi

AM_CONDITIONAL([enable_python], [test "$have_python" = yes])


AC_ARG_WITH([static-libsepol],
        [AC_HELP_STRING([--with-static-libsepol=PATH],
		[libsepol.a library to build against. Optional])],
        [AC_MSG_CHECKING([for libsepol.a ])]
        [if @<:@ -f "$with_static_libsepol/libsepol.a" @:>@ ; then
                        AC_MSG_RESULT([$with_static_libsepol/libsepol.a found])
                        AC_SUBST([LIBSEPOL_A_PATH], 
				[[$with_static_libsepol/libsepol.a]])
        elif @<:@ -f "$with_static_libsepol" @:>@ ; then
                        AC_MSG_RESULT([$with_static_libsepol ok])
                        AC_SUBST([LIBSEPOL_A_PATH], [[$with_static_libsepol]])
        else
                AC_MSG_RESULT([no found])
                AC_MSG_WARN([[Cannot build libpyaudit2why.so python wrappper. 
		Try --with-static-libsepol=PATH]])

        fi],
        [AC_MSG_CHECKING([for libsepol.a in $prefix/lib])]
        [if @<:@ -f "$prefix/lib/libsepol.a" @:>@ ; then
                AC_MSG_RESULT([$prefix/lib/libsepol.a found])
                AC_SUBST([LIBSEPOL_A_PATH], [[$prefix/lib/libsepol.a]])
        else
                AC_MSG_RESULT([not found])
                AC_MSG_WARN([[Cannot build libpyaudit2why.so python wrappper. 
		Try --with-static-libsepol=PATH]])
        fi]
)


AM_CONDITIONAL([have_sepol],[test -n "$LIBSEPOL_A_PATH" ])

AC_ARG_WITH([policyname],
	[AC_HELP_STRING([--with-policyname],
		[Name of policy type for configuration (default: targeted)])],
	[],
	[with_policyname=targeted]
)

AC_SUBST([policyname],[$with_policyname])

AC_ARG_ENABLE([swig],
	[AC_HELP_STRING([--disable-swig],
		[Disable regeneration of python c interface (default=no)])],
	[_enable_swig=$enableval],
	[_enable_swig=yes]
)
# Hault the config if we are asked for swig, but not swig is found
if test "$_enable_swig" = "yes" -a -z "$SWIG" ; then
	AC_MSG_ERROR([Cannot find swig interface gemerator in PATH, 
		Disable python c-inteferace regeneration with --disable-swig, 
		or install swig])
fi

# If libpy*.so wrapper cannot be built, then do not rebuild swig interface
# even if swig is available, and do not install selinux/__init__.py
if test "$have_python" != "yes" ; then
	_enable_swig=no
	AC_MSG_NOTICE([Swig interface does not need to be regenerated 
		because libpyselinux.so wrapper cannot be built])
fi

# slip in fake swig if needed
if test "$_enable_swig" != "yes" ; then
	AC_SUBST([SWIG],[/bin/true])
fi

AC_CONFIG_FILES([Makefile
		src/Makefile
		utils/Makefile
		man/Makefile
		include/Makefile])

VERSION=`cat $srcdir/VERSION`
if test "$VERSION" = "" ; then
	VERSION=svn
fi

AC_OUTPUT

PRINT='echo -n -e '
$PRINT "\n*** Libselinux Configuration summary ***\n"

if test "$have_python" != yes ; then
 $PRINT "\taudit2why\t\t= no "
 $PRINT "(try --with-python=/usr/include/python$PYTHON_VERSION) \n"
 $PRINT "\tlibpyselinux.so\t\t= no "
 $PRINT "(try --with-python=/usr/include/python$PYTHON_VERSION) \n"
else
 $PRINT "\taudit2why\t\t= yes (Using python headers $with_python) \n"
 $PRINT "\tlibpyselinux.so\t\t= yes\n"
 $PRINT "\tPython site folder\t= $pythondir\n"
fi

if test -n "$LIBSEPOL_A_PATH" ; then
 $PRINT "\tlibpyaudit2why.so\t= yes (Using $LIBSEPOL_A_PATH) \n"
else
 $PRINT "\tlibpyaudit2why.so\t= no "
 $PRINT "(try --with-static-libsepol=/path/to/libsepol.a)\n"
fi
$PRINT "\tlibselinux.so\t\t= yes\n"
$PRINT "\tAVC Support\t\t= $_enable_avc\n"
$PRINT "\tBoolean Support\t\t= $_enable_bool\n"
$PRINT "\tRPM Support\t\t= $_enable_rpm\n"
$PRINT "\tSELinux utlities\t= yes\n"
$PRINT "\tInstall Man pages\t= $_enable_docs\n"
$PRINT "\tSELinux Type\t\t= $with_policyname\n"
$PRINT "\tRegenerate py wrapper\t= $_enable_swig\n"
$PRINT "------------------------------------------------------------\n" 
