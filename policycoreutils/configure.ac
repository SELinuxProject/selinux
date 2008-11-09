#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(policycoreutils, VERSION, selinux@tycho.nsa.gov)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([run_init/run_init.c])
AC_CONFIG_HEADER([config.h])

AM_PATH_PYTHON

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

AM_PROG_CC_C_O

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UID_T
AC_TYPE_UINT32_T

AC_CHECK_LIB([dl], [dlopen])

AC_SEARCH_LIBS([selinux_init_load_policy],[selinux],
        [],
        [AC_MSG_ERROR([[Compatible libselinux not found.]])]
)

AC_SEARCH_LIBS([sepol_policydb_read],[sepol],
        [],
        [AC_MSG_ERROR([[Compatible libsepol not found.]])]
)

AC_SEARCH_LIBS([sepol_set_expand_consume_base],[sepol],
        [],
        [AC_MSG_ERROR([[Compatible libsepol not found.]])]
)


AC_ARG_WITH([static-libsepol],
	[AC_HELP_STRING([--with-static-libsepol=PATH],
		[Required for semodule_deps])],
	[AC_MSG_CHECKING([for libsepol.a ])]
	[if @<:@ -f "$with_static_libsepol/libsepol.a" @:>@ ; then
		AC_MSG_RESULT([$with_static_libsepol/libsepol.a found])
		HAVE_semodule_deps=yes
		AC_SUBST([LIBSEPOL_A_PATH], [[$with_static_libsepol/libsepol.a]])
	elif @<:@ -f "$with_static_libsepol" @:>@ ; then
			AC_MSG_RESULT([$with_static_libsepol ok])
			HAVE_semodule_deps=yes
			AC_SUBST([LIBSEPOL_A_PATH], [[$with_static_libsepol]])
	else
		AC_MSG_RESULT([no found])
		HAVE_semodule_deps=no
		AC_MSG_NOTICE([[semodule_deps cannot be built without libsepol.a ]])
	fi],
	[AC_MSG_CHECKING([for libsepol.a in $prefix/lib])]
	[if @<:@ -f "$prefix/lib/libsepol.a" @:>@ ; then
		AC_MSG_RESULT([$prefix/lib/libsepol.a found])
		HAVE_semodule_deps=yes
		AC_SUBST([LIBSEPOL_A_PATH], [[$prefix/lib/libsepol.a]])
	else
		AC_MSG_RESULT([not found])
		HAVE_semodule_deps=no
		AC_MSG_NOTICE([[semodule_deps cannot be built without libsepol.a. 
			Please use --with-static-libsepol=PATH]])
	fi]
)

AM_CONDITIONAL([BUILD_semodule_deps],[test "x$HAVE_semodule_deps" = xyes])

AC_SEARCH_LIBS([forkpty], [util],
	[HAVE_run_init=yes],
	[HAVE_run_init=no]
	[AC_MSG_NOTICE([*** Not building run_init ***])]
)
AM_CONDITIONAL([BUILD_run_init],[test "x$HAVE_run_init" = xyes])

#check for libaudit
AC_SEARCH_LIBS([audit_open], [audit],
	[AC_CHECK_HEADERS([libaudit.h],[HAVE_LIBAUDIT=yes],[])],
	[AC_MSG_NOTICE([ *** Disabling kernel audit functionality *** ])])
AM_CONDITIONAL([have_libaudit],[test "x$HAVE_LIBAUDIT" = xyes])

AC_SEARCH_LIBS([pam_authenticate], [pam],
	[AC_SEARCH_LIBS([misc_conv],[pam_misc],
		[AC_CHECK_HEADERS([security/pam_appl.h],[have_pam=yes],
			[AC_MSG_NOTICE([ *** PAM functionality disabled ***])])],
		[AC_MSG_NOTICE([*** PAM Functionality disabled ***])]
		[have_pam=no]
	)],
	[AC_MSG_NOTICE([*** PAM Functionality disabled ***])]
	[have_pam=no]
)
AM_CONDITIONAL([HAVE_PAM], [ test "x$have_pam" = xyes])

if test "x$have_pam" != xyes ; then
	AC_SEARCH_LIBS([crypt], [crypt],[],
		[AC_MSG_ERROR([Must have either PAM or crypt libs to continue])]
	)
fi


AC_SEARCH_LIBS([semanage_connect], [semanage],
	[HAVE_semanage=yes],
	[HAVE_semanage=no]
	[AC_MSG_NOTICE([*** Not building semodule ***])]
	[AC_MSG_NOTICE([*** Not building setsebool ***])]
)
AM_CONDITIONAL([BUILD_semodule],[test "x$HAVE_semanage" = xyes])
AM_CONDITIONAL([BUILD_setsebool],[test "x$HAVE_semanage" = xyes])


AC_ARG_WITH([startupdir],
        [AC_HELP_STRING([--with-startupdir=PATH],
		[Path to startup script's folder (eg /etc/rc.d/init.d)])],
        [],
        [with_startupdir=no]
)
if test "$with_startupdir" != "no" ; then
        AC_SUBST([STARTUP_DIR],[$with_startupdir])
else
	AC_SUBST([STARTUP_DIR],[$sysconfdir/rc.d/init.d])
fi


AC_ARG_WITH([pamdir],
	[AC_HELP_STRING([--with-pamdir=x],
		[Location of pam module directory (default: $sysconfdir/pam.d)])],
	[],
	[with_pamdir=$sysconfdir/pam.d],
)
AC_SUBST([pamdir],[$with_pamdir])

AC_ARG_WITH([pythonver],
	[AC_HELP_STRING([--with-pythonver=x],[Python version (eg 2.4) ])],
        [],
        [with_pythonver=$PYTHON_VERSION]
)

if test -n "$with_pythonver" ; then
        AC_SUBST([pythondir],[$libdir/python$with_pythonver/site-packages])
        AC_SUBST([pyexecdir],[$libdir/python$with_pythonver/site-packages])
fi

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h libintl.h \
	limits.h locale.h shadow.h \
	stdint.h stdio_ext.h stdlib.h \
	string.h sys/vfs.h syslog.h \
	termios.h unistd.h utmp.h])

AC_CHECK_HEADERS([sys/inotify.h])

AC_CHECK_HEADERS([selinux/selinux.h],[],
	[AC_MSG_ERROR([libselinux header files missing])])

AC_CHECK_HEADERS([semanage/modules.h],[],
	[AC_MSG_ERROR([libsepol header files missing])])

#AM_PATH_PYTHON(,, [:])
#AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

AC_CHECK_HEADER([sys/inotify.h],
       [AC_DEFINE([HAVE_SYS_INOTIFY_H], 1,  
		[Define to 1 if <sys/inotify.h> is available])]
       [have_sys_inotify=yes]
        ,
        [AC_MSG_WARN([[<sys/inotify.h> not found, cannot build restorecond]])]
        [have_sys_inotify=no]
)

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([atexit endpwent getdelim \
	getpass getspnam getusershell \
	memset munmap realpath setenv \
	setlocale strcasecmp strchr \
	strcspn strdup strerror \
	strndup strrchr strspn strtol])

AC_CONFIG_FILES([
	semanage/Makefile
	load_policy/Makefile
	newrole/Makefile
	secon/Makefile
	audit2allow/Makefile
	audit2why/Makefile
	scripts/Makefile
	restorecond/Makefile
	run_init/Makefile
	setsebool/Makefile
	sestatus/Makefile
	semodule/Makefile
	semodule_deps/Makefile
	semodule_package/Makefile
	semodule_link/Makefile
	semodule_expand/Makefile
	setfiles/Makefile
	Makefile])

# Pickup the version info from the source directory if available
VERSION=`cat $srcdir/VERSION`
if test "$VERSION" = "" ; then
        VERSION=git
fi

AC_OUTPUT

PRINT='echo -n -e '

$PRINT "\nPolicycoreutils Configuration Summary:\n"
	$PRINT "\tsemanage\t\t= yes\n"
	$PRINT "\tload_policy\t\t= yes\n"
	$PRINT "\tnewrole\t\t\t= yes\n"
	$PRINT "\tsecon\t\t\t= yes\n"
	$PRINT "\taudit2allow\t\t= yes\n"
	$PRINT "\taudit2why\t\t= yes\n"
	$PRINT "\trestorecond\t\t= yes\n"
        $PRINT  "\trun_init\t\t= $HAVE_run_init\n"
	$PRINT "\tscripts\t\t\t= yes\n"
	$PRINT "\tsestatus\t\t= yes\n"
	$PRINT "\tsemodule_package\t= yes\n"
	$PRINT "\tsemodule\t\t= $HAVE_semanage\n"
	$PRINT "\tsetsebool\t\t= $HAVE_semanage\n"
	$PRINT "\tsemodule_link\t\t= yes\n"
	$PRINT "\tsemodule_expand\t\t= yes\n"
	$PRINT "\tsemodule_deps\t\t= $HAVE_semodule_deps\n"
	$PRINT "\tsetfiles\t\t= yes\n"
	$PRINT "\tPAM Support\t\t= $have_pam\n"
	$PRINT "\tPAM Module Path\t\t= $pamdir\n"
if test -z "$LIBSEPOL_A_PATH" ; then
	LIBSEPOL_A_PATH="Not available"
fi
	$PRINT "\tlibsepol.a\t\t= $LIBSEPOL_A_PATH\n"
	$PRINT "\tStartup Script folder\t= $STARTUP_DIR\n"
	$PRINT "\tPython Packages folder\t= $pythondir\n"
$PRINT "------------------------------------------------------------\n"
