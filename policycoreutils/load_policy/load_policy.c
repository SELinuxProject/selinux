#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <selinux/selinux.h>
#include <sepol/sepol.h>
#ifdef USE_NLS
#include <locale.h>		/* for setlocale() */
#include <libintl.h>		/* for gettext() */
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif
#ifndef PACKAGE
#define PACKAGE "policycoreutils"	/* the name of this package lang translation */
#endif

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	fprintf(stderr, _("usage:  %s [-qi]\n"), progname);
	exit(1);
}

int main(int argc, char **argv)
{
	int ret, opt, quiet = 0, nargs, init=0, enforce=0;

#ifdef USE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	while ((opt = getopt(argc, argv, "bqi")) > 0) {
		switch (opt) {
		case 'b':
			fprintf(stderr, "%s:  Warning! The -b option is no longer supported, booleans are always preserved across reloads.  Continuing...\n",
				argv[0]);
			break;
		case 'q':
			quiet = 1;
			sepol_debug(0);
			break;
		case 'i':
			init = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	nargs = argc - optind;
	if (nargs > 2)
		usage(argv[0]);
	if (nargs >= 1 && !quiet) {
			fprintf(stderr,
				"%s:  Warning!  Policy file argument (%s) is no longer supported, installed policy is always loaded.  Continuing...\n",
				argv[0], argv[optind++]);
	}
	if (nargs == 2 && ! quiet) {
		fprintf(stderr,
			"%s:  Warning!  Boolean file argument (%s) is no longer supported, installed booleans file is always used.  Continuing...\n",
			argv[0], argv[optind++]);
	}
	if (init) {
		ret = selinux_init_load_policy(&enforce);
		if (ret != 0 ) {
			if (enforce > 0) {
				/* SELinux in enforcing mode but load_policy failed */
				fprintf(stderr,
						_("%s:  Can't load policy and enforcing mode requested:  %s\n"),
						argv[0], strerror(errno));
				exit(3);
			}
		}
	}
	else {
		ret = selinux_mkload_policy(0);
	}
	if (ret < 0) {
		fprintf(stderr, _("%s:  Can't load policy:  %s\n"),
			argv[0], strerror(errno));
		exit(2);
	}
	exit(0);
}
