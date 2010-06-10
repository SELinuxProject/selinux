#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/mount.h>
#include <pwd.h>
#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cap-ng.h>
#include <getopt.h>		/* for getopt_long() form of getopt() */
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <selinux/selinux.h>
#include <selinux/context.h>	/* for context-mangling functions */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef USE_NLS
#include <locale.h>		/* for setlocale() */
#include <libintl.h>		/* for gettext() */
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif

/**
 * This function will drop all capabilities 
 * Returns zero on success, non-zero otherwise
 */
static int drop_capabilities(uid_t uid)
{
	capng_clear(CAPNG_SELECT_BOTH);

	if (capng_lock() < 0) 
		return -1;
	/* Change uid */
	if (setresuid(uid, uid, uid)) {
		fprintf(stderr, _("Error changing uid, aborting.\n"));
		return -1;
	}
	return capng_apply(CAPNG_SELECT_BOTH);
}

#define DEFAULT_PATH "/usr/bin:/bin"
static	int verbose = 0;

/**
 * Take care of any signal setup
 */
static int set_signal_handles(void)
{
	sigset_t empty;

	/* Empty the signal mask in case someone is blocking a signal */
	if (sigemptyset(&empty)) {
		fprintf(stderr, "Unable to obtain empty signal set\n");
		return -1;
	}

	(void)sigprocmask(SIG_SETMASK, &empty, NULL);

	/* Terminate on SIGHUP. */
	if (signal(SIGHUP, SIG_DFL) == SIG_ERR) {
		perror("Unable to set SIGHUP handler");
		return -1;
	}

	return 0;
}

/**
 * This function makes sure the mounted directory is owned by the user executing
 * seunshare.
 * If so, it returns 0. If it can not figure this out or they are different, it returns -1.
 */
static int verify_mount(const char *mntdir, struct passwd *pwd) {
	struct stat sb;
	if (stat(mntdir, &sb) == -1) {
		fprintf(stderr, _("Invalid mount point %s: %s\n"), mntdir, strerror(errno));
		return -1;
	}
	if (sb.st_uid != pwd->pw_uid) {
		errno = EPERM;
		syslog(LOG_AUTHPRIV | LOG_ALERT, "%s attempted to mount an invalid directory, %s", pwd->pw_name, mntdir);
		perror(_("Invalid mount point, reporting to administrator"));
		return -1;
	}
	return 0;
}

/**
 * This function checks to see if the shell is known in /etc/shells.
 * If so, it returns 0. On error or illegal shell, it returns -1.
 */
static int verify_shell(const char *shell_name)
{
	int rc = -1;
	const char *buf;

	if (!(shell_name && shell_name[0]))
		return rc;

	while ((buf = getusershell()) != NULL) {
		/* ignore comments */
		if (*buf == '#')
			continue;

		/* check the shell skipping newline char */
		if (!strcmp(shell_name, buf)) {
			rc = 1;
			break;
		}
	}
	endusershell();
	return rc;
}

static int seunshare_mount(const char *src, const char *dst, struct passwd *pwd) {
	if (verbose)
		printf("Mount %s on %s\n", src, dst);
	if (mount(dst, dst,  NULL, MS_BIND, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), dst, dst, strerror(errno));
		return -1;
	}

	if (mount(dst, dst, NULL, MS_PRIVATE, NULL) < 0) {
		fprintf(stderr, _("Failed to make %s private: %s\n"), dst, strerror(errno));
		return -1;
	}

	if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), src, dst, strerror(errno));
		return -1;
	}

	if (verify_mount(dst, pwd) < 0) 
		return -1;
}

#define USAGE_STRING _("USAGE: seunshare [ -v ] [ -t tmpdir ] [ -h homedir ] -- CONTEXT executable [args] ")

int main(int argc, char **argv) {
	int rc;
	int status = -1;

	security_context_t scontext;

	int flag_index;		/* flag index in argv[] */
	int clflag;		/* holds codes for command line flags */
	char *tmpdir_s = NULL;	/* tmpdir spec'd by user in argv[] */
	char *homedir_s = NULL;	/* homedir spec'd by user in argv[] */

	const struct option long_options[] = {
		{"homedir", 1, 0, 'h'},
		{"tmpdir", 1, 0, 't'},
		{"verbose", 1, 0, 'v'},
		{NULL, 0, 0, 0}
	};

	uid_t uid = getuid();

	if (!uid) {
		fprintf(stderr, _("Must not be root"));
		return -1;
	}

	struct passwd *pwd=getpwuid(uid);
	if (!pwd) {
		perror(_("getpwduid failed"));
		return -1;
	}

	if (verify_shell(pwd->pw_shell) < 0) {
		fprintf(stderr, _("Error!  Shell is not valid.\n"));
		return -1;
	}

	while (1) {
		clflag = getopt_long(argc, argv, "h:t:", long_options,
				     &flag_index);
		if (clflag == -1)
			break;

		switch (clflag) {
		case 't':
			tmpdir_s = optarg;
			if (verify_mount(tmpdir_s, pwd) < 0) return -1;
			break;
		case 'h':
			homedir_s = optarg;
			if (verify_mount(homedir_s, pwd) < 0) return -1;
			if (verify_mount(pwd->pw_dir, pwd) < 0) return -1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			fprintf(stderr, "%s\n", USAGE_STRING);
			return -1;
		}
	}

	if (! homedir_s && ! tmpdir_s) {
		fprintf(stderr, _("Error: tmpdir and/or homedir required \n"),
			"%s\n", USAGE_STRING);
		return -1;
	}

	if (argc - optind < 2) {
		fprintf(stderr, _("Error: context and executable required \n"),
			"%s\n", USAGE_STRING);
		return -1;
	}

	scontext = argv[optind++];
	
	if (set_signal_handles())
		return -1;

        if (unshare(CLONE_NEWNS) < 0) {
		perror(_("Failed to unshare"));
		return -1;
	}

	if (homedir_s && tmpdir_s && (strncmp(pwd->pw_dir, tmpdir_s, strlen(pwd->pw_dir)) == 0)) {
	    if (seunshare_mount(tmpdir_s, "/tmp", pwd) < 0)
		    return -1;
	    if (seunshare_mount(homedir_s, pwd->pw_dir, pwd) < 0)
		    return -1;
	} else {			
		if (homedir_s && seunshare_mount(homedir_s, pwd->pw_dir, pwd) < 0)
				return -1;
				
		if (tmpdir_s && seunshare_mount(tmpdir_s, "/tmp", pwd) < 0)
				return -1;
	}

	if (drop_capabilities(uid)) {
		perror(_("Failed to drop all capabilities"));
		return -1;
	}

	int child = fork();
	if (child == -1) {
		perror(_("Unable to fork"));
		return -1;
	}

	if (!child) {
		char *display=NULL;
		/* Construct a new environment */
		char *d = getenv("DISPLAY");
		if (d) {
			display =  strdup(d);
			if (!display) {
				perror(_("Out of memory"));
				exit(-1);
			}
		}

		if ((rc = clearenv())) {
			perror(_("Unable to clear environment"));
			free(display);
			exit(-1);
		}
		
		if (setexeccon(scontext)) {
			fprintf(stderr, _("Could not set exec context to %s.\n"),
				scontext);
			free(display);
			exit(-1);
		}

		if (display) 
			rc |= setenv("DISPLAY", display, 1);
		rc |= setenv("HOME", pwd->pw_dir, 1);
		rc |= setenv("SHELL", pwd->pw_shell, 1);
		rc |= setenv("USER", pwd->pw_name, 1);
		rc |= setenv("LOGNAME", pwd->pw_name, 1);
		rc |= setenv("PATH", DEFAULT_PATH, 1);
		
		if (chdir(pwd->pw_dir)) {
			perror(_("Failed to change dir to homedir"));
			exit(-1);
		}
		setsid();
		execv(argv[optind], argv + optind);
		free(display);
		perror("execv");
		exit(-1);
	} else {
		waitpid(child, &status, 0);
	}

	return status;
}
