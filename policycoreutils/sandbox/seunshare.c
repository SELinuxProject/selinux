#define _GNU_SOURCE
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/mount.h>
#include <pwd.h>
#include <sched.h>
#include <libcgroup.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
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

#ifndef MS_REC
#define MS_REC 1<<14
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE 1<<18
#endif

#define BUF_SIZE 1024
#define DEFAULT_PATH "/usr/bin:/bin"
#define USAGE_STRING _("USAGE: seunshare [ -v ] [ -C ] [ -c ] [ -t tmpdir ] [ -h homedir ] [ -Z CONTEXT ] -- executable [args] ")

static int verbose = 0;

static capng_select_t cap_set = CAPNG_SELECT_BOTH;

/**
 * This function will drop all capabilities.
 */
static int drop_caps()
{
	if (capng_have_capabilities(cap_set) == CAPNG_NONE)
		return 0;
	capng_clear(cap_set);
	if (capng_lock() == -1 || capng_apply(cap_set) == -1) {
		fprintf(stderr, _("Failed to drop all capabilities\n"));
		return -1;
	}
	return 0;
}

/**
 * This function will drop all privileges.
 */
static int drop_privs(uid_t uid)
{
	if (drop_caps() == -1 || setresuid(uid, uid, uid) == -1) {
		fprintf(stderr, _("Failed to drop privileges\n"));
		return -1;
	}
	return 0;
}

/**
 * Take care of any signal setup.
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

#define status_to_retval(status,retval) do { \
	if ((status) == -1) \
		retval = -1; \
	else if (WIFEXITED((status))) \
		retval = WEXITSTATUS((status)); \
	else if (WIFSIGNALED((status))) \
		retval = 128 + WTERMSIG((status)); \
	else \
		retval = -1; \
	} while(0)

/**
 * Spawn external command using system() with dropped privileges.
 * TODO: avoid system() and use exec*() instead
 */
static int spawn_command(const char *cmd, uid_t uid){
	int child;
	int status = -1;

	if (verbose > 1)
		printf("spawn_command: %s\n", cmd);

	child = fork();
	if (child == -1) {
		perror(_("Unable to fork"));
		return status;
	}

	if (child == 0) {
		if (drop_privs(uid) != 0) exit(-1);

		status = system(cmd);
		status_to_retval(status, status);
		exit(status);
	}

	waitpid(child, &status, 0);
	status_to_retval(status, status);
	return status;
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
 * Check file/directory ownership, struct stat * must be passed to the
 * functions.
 */
static int check_owner_uid(uid_t uid, const char *file, struct stat *st) {
	if (S_ISLNK(st->st_mode)) {
		fprintf(stderr, _("Error: %s must not be a symbolic link\n"), file);
		return -1;
	}
	if (st->st_uid != uid) {
		fprintf(stderr, _("Error: %s not owned by UID %d\n"), file, uid);
		return -1;
	}
	return 0;
}

static int check_owner_gid(gid_t gid, const char *file, struct stat *st) {
	if (S_ISLNK(st->st_mode)) {
		fprintf(stderr, _("Error: %s must not be a symbolic link\n"), file);
		return -1;
	}
	if (st->st_gid != gid) {
		fprintf(stderr, _("Error: %s not owned by GID %d\n"), file, gid);
		return -1;
	}
	return 0;
}

#define equal_stats(one,two) \
	((one)->st_dev == (two)->st_dev && (one)->st_ino == (two)->st_ino && \
	 (one)->st_uid == (two)->st_uid && (one)->st_gid == (two)->st_gid && \
	 (one)->st_mode == (two)->st_mode)

/**
 * Sanity check specified directory.  Store stat info for future comparison, or
 * compare with previously saved info to detect replaced directories.
 * Note: This function does not perform owner checks.
 */
static int verify_directory(const char *dir, struct stat *st_in, struct stat *st_out) {
	struct stat sb;

	if (st_out == NULL) st_out = &sb;

	if (lstat(dir, st_out) == -1) {
		fprintf(stderr, _("Failed to stat %s: %s\n"), dir, strerror(errno));
		return -1;
	}
	if (! S_ISDIR(st_out->st_mode)) {
		fprintf(stderr, _("Error: %s is not a directory: %s\n"), dir, strerror(errno));
		return -1;
	}
	if (st_in && !equal_stats(st_in, st_out)) {
		fprintf(stderr, _("Error: %s was replaced by a different directory\n"), dir);
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
	if (mount(dst, dst,  NULL, MS_BIND | MS_REC, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), dst, dst, strerror(errno));
		return -1;
	}

	if (mount(dst, dst, NULL, MS_PRIVATE | MS_REC, NULL) < 0) {
		fprintf(stderr, _("Failed to make %s private: %s\n"), dst, strerror(errno));
		return -1;
	}

	if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), src, dst, strerror(errno));
		return -1;
	}

	if (verify_mount(dst, pwd) < 0) 
		return -1;
}

/**
 * Error logging used by cgroups code.
 */
static int sandbox_error(const char *string)
{
	fprintf(stderr, string);
	syslog(LOG_AUTHPRIV | LOG_ALERT, string);
	exit(-1);

}

/**
 * Regular expression match.
 */
static int match(const char *string, char *pattern)
{
	int status;
	regex_t re;
	if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {
		return 0;
	}
	status = regexec(&re, string, (size_t)0, NULL, 0);
	regfree(&re);
	if (status != 0) {
		return 0;
	}
	return 1;
}

/**
 * Apply cgroups settings from the /etc/sysconfig/sandbox config file.
 */
static int setup_cgroups()
{
	char *cpus = NULL;	/* which CPUs to use */
	char *cgroupname = NULL;/* name for the cgroup */
	char *mem = NULL;	/* string for memory amount to pass to cgroup */
	int64_t memusage = 0;	/* amount of memory to use max (percent) */
	int cpupercentage = 0;  /* what percentage of cpu to allow usage */
	FILE* fp;
	char buf[BUF_SIZE];
	char *tok = NULL;
	int rc = -1;
	char *str = NULL;
	const char* fname = "/etc/sysconfig/sandbox";

	if ((fp = fopen(fname, "rt")) == NULL) {
		fprintf(stderr, "Error opening sandbox config file.");
		return rc;
	}
	while(fgets(buf, BUF_SIZE, fp) != NULL) {
		/* Skip comments */
		if (buf[0] == '#') continue;

		/* Copy the string, ignoring whitespace */
		int len = strlen(buf);
		free(str);
		str = malloc((len + 1) * sizeof(char));
		if (!str)
			goto err;

		int ind = 0;
		int i;
		for (i = 0; i < len; i++) {
			char cur = buf[i];
			if (cur != ' ' && cur != '\t') {
				str[ind] = cur;
				ind++;
			}
		}
		str[ind] = '\0';

		tok = strtok(str, "=\n");
		if (tok != NULL) {
			if (!strcmp(tok, "CPUAFFINITY")) {
				tok = strtok(NULL, "=\n");
				cpus = strdup(tok);
				if (!strcmp(cpus, "ALL")) {
					free(cpus);
					cpus = NULL;
				}
			} else if (!strcmp(tok, "MEMUSAGE")) {
				tok = strtok(NULL, "=\n");
				if (match(tok, "^[0-9]+[kKmMgG%]")) {
					char *ind = strchr(tok, '%');
					if (ind != NULL) {
						*ind = '\0';;
						memusage = atoi(tok);
					} else {
						mem = strdup(tok);
					}
				} else {
					fprintf(stderr, "Error parsing config file.");
					goto err;
				}

			} else if (!strcmp(tok, "CPUUSAGE")) {
				tok = strtok(NULL, "=\n");
				if (match(tok, "^[0-9]+\%")) {
					char* ind = strchr(tok, '%');
					*ind = '\0';
					cpupercentage = atoi(tok);
				} else {
					fprintf(stderr, "Error parsing config file.");
					goto err;
				}
			} else if (!strcmp(tok, "NAME")) {
				tok = strtok(NULL, "=\n");
				cgroupname = strdup(tok);
			} else {
				continue;
			}
		}

	}
	if (mem == NULL) {
		long phypz = sysconf(_SC_PHYS_PAGES);
		long psize = sysconf(_SC_PAGE_SIZE);
		memusage = phypz * psize * (float) memusage / 100.0;
	}

	cgroup_init();

	int64_t current_runtime = 0;
	int64_t current_period = 0 ;
	int64_t current_mem = 0;
	char *curr_cpu_path = NULL;
	char *curr_mem_path = NULL;
	int ret  = cgroup_get_current_controller_path(getpid(), "cpu", &curr_cpu_path);
	if (ret) {
		sandbox_error("Error while trying to get current controller path.\n");
	} else {
		struct cgroup *curr = cgroup_new_cgroup(curr_cpu_path);
		cgroup_get_cgroup(curr);
		cgroup_get_value_int64(cgroup_get_controller(curr, "cpu"), "cpu.rt_runtime_us", &current_runtime);
		cgroup_get_value_int64(cgroup_get_controller(curr, "cpu"), "cpu.rt_period_us", &current_period);
	}

	ret  = cgroup_get_current_controller_path(getpid(), "memory", &curr_mem_path);
	if (ret) {
		sandbox_error("Error while trying to get current controller path.\n");
	} else {
		struct cgroup *curr = cgroup_new_cgroup(curr_mem_path);
		cgroup_get_cgroup(curr);
		cgroup_get_value_int64(cgroup_get_controller(curr, "memory"), "memory.limit_in_bytes", &current_mem);
	}

	if (((float) cpupercentage)  / 100.0> (float)current_runtime / (float) current_period) {
		sandbox_error("CPU usage restricted!\n");
		goto err;
	}

	if (mem == NULL) {
		if (memusage > current_mem) {
			sandbox_error("Attempting to use more memory than allowed!");
			goto err;
		}
	}

	long nprocs = sysconf(_SC_NPROCESSORS_ONLN);

	struct sched_param sp;
	sp.sched_priority = sched_get_priority_min(SCHED_FIFO);
	sched_setscheduler(getpid(), SCHED_FIFO, &sp);
	struct cgroup *sandbox_group = cgroup_new_cgroup(cgroupname);
	cgroup_add_controller(sandbox_group, "memory");
	cgroup_add_controller(sandbox_group, "cpu");

	if (mem == NULL) {
		if (memusage > 0) {
			cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", memusage);
		}
	} else {
		cgroup_set_value_string(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", mem);
	}
	if (cpupercentage > 0) {
		cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "cpu"), "cpu.rt_runtime_us",
					(float) cpupercentage / 100.0 * 60000);
		cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "cpu"), "cpu.rt_period_us",60000 * nprocs);
	}
	if (cpus != NULL) {
		cgroup_set_value_string(cgroup_get_controller(sandbox_group, "cpu"), "cgroup.procs",cpus);
	}

	uint64_t allocated_mem;
	if (cgroup_get_value_uint64(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", &allocated_mem) > current_mem) {
		sandbox_error("Attempting to use more memory than allowed!\n");
		goto err;
	}

	rc = cgroup_create_cgroup(sandbox_group, 1);
	if (rc != 0) {
		sandbox_error("Failed to create group.  Ensure that cgconfig service is running. \n");
		goto err;
	}

	cgroup_attach_task(sandbox_group);

	rc = 0;
err:
	fclose(fp);
	free(str);
	free(mem);
	free(cgroupname);
	free(cpus);
	return rc;
}

int main(int argc, char **argv) {
	int rc;
	int status = -1;

	security_context_t scontext = NULL;

	int flag_index;		/* flag index in argv[] */
	int clflag;		/* holds codes for command line flags */
	char *tmpdir_s = NULL;	/* tmpdir spec'd by user in argv[] */
	char *homedir_s = NULL;	/* homedir spec'd by user in argv[] */
	int usecgroups = 0;

	const struct option long_options[] = {
		{"homedir", 1, 0, 'h'},
		{"tmpdir", 1, 0, 't'},
		{"verbose", 1, 0, 'v'},
		{"cgroups", 1, 0, 'c'},
		{"context", 1, 0, 'Z'},
		{"capabilities", 1, 0, 'C'},
		{NULL, 0, 0, 0}
	};

	uid_t uid = getuid();
/*
	if (!uid) {
		fprintf(stderr, _("Must not be root"));
		return -1;
	}
*/

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
		clflag = getopt_long(argc, argv, "Ccvh:t:Z:", long_options, NULL);
		if (clflag == -1)
			break;

		switch (clflag) {
		case 't':
			if (!(tmpdir_s = realpath(optarg, NULL))) {
				fprintf(stderr, _("Invalid mount point %s: %s\n"), optarg, strerror(errno));
				return -1;
			}
			if (verify_mount(tmpdir_s, pwd) < 0) return -1;
			break;
		case 'h':
			if (!(homedir_s = realpath(optarg, NULL))) {
				fprintf(stderr, _("Invalid mount point %s: %s\n"), optarg, strerror(errno));
				return -1;
			}
			if (verify_mount(homedir_s, pwd) < 0) return -1;
			if (verify_mount(pwd->pw_dir, pwd) < 0) return -1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'c':
			usecgroups = 1;
			break;
		case 'C':
			cap_set = CAPNG_SELECT_CAPS;
			break;
		case 'Z':
			scontext = strdup(optarg);
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

	if (argc - optind < 1) {
		fprintf(stderr, _("Error: executable required \n %s \n"), USAGE_STRING);
		return -1;
	}

	if (set_signal_handles())
		return -1;

	if (usecgroups && setup_cgroups() < 0)
		return  -1;

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

	if (drop_privs(uid))
		return -1;

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

		if (scontext) {
			if (setexeccon(scontext)) {
				fprintf(stderr, _("Could not set exec context to %s.\n"),
					scontext);
				free(display);
				exit(-1);
			}
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

	free(tmpdir_s);
	free(homedir_s);
	free(scontext);

	return status;
}
