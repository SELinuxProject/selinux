#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(sepolgen, VERSION, BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE


AM_PATH_PYTHON

# Checks for programs.
AC_PROG_INSTALL


AC_ARG_WITH([pythonver],
	[AC_HELP_STRING([--with-pythonver=2.X],
		[eg 2.4])],
	[],
	[with_pythonver=$PYTHON_VERSION]
)

if test -n "$with_pythonver" ; then
	AC_SUBST([pythondir],[$libdir/python$with_pythonver/site-packages])
	AC_SUBST([pyexecdir],[$libdir/python$with_pythonver/site-packages])
fi

AC_CONFIG_FILES([Makefile
                 src/sepolgen/Makefile
                 src/share/Makefile])



VERSION=`cat $srcdir/VERSION`
if test "$VERSION" = "" ; then
        VERSION=svn
fi

AC_OUTPUT

PRINT='echo -n -e '



$PRINT "\n$PACKAGE Configuration Summary:\n"
$PRINT "\tPython Packages folder\t= $pythondir\n"
$PRINT "------------------------------------------------------------\n"

