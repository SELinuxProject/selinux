/*
 * Authors: Dan Walsh <dwalsh@redhat.com>
 * Authors: Thomas Liu <tliu@fedoraproject.org>
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <signal.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/mount.h>
#include <glob.h>
#include <pwd.h>
#include <sched.h>
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
#include <fcntl.h>

#include <selinux/selinux.h>
#include <selinux/context.h>	/* for context-mangling functions */
#include <dirent.h>

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

#ifndef MS_SLAVE
#define MS_SLAVE 1<<19
#endif

#ifndef PACKAGE
#define PACKAGE "policycoreutils"	/* the name of this package lang translation */
#endif

#define BUF_SIZE 1024
#define DEFAULT_PATH "/usr/bin:/bin"
#define USAGE_STRING _("USAGE: seunshare [ -v ] [ -C ] [ -k ] [ -t tmpdir ] [ -h homedir ] \
[ -r runuserdir ] [ -P pipewiresocket ] [ -W waylandsocket ] [ -Z CONTEXT ] -- executable [args] ")

#define strdup_or_err(args, index, src) do {	\
		args[index] = strdup(src); \
		if (! args[index]) \
			goto err; \
	} while(0)

static int verbose = 0;
static int child = 0;

static capng_select_t cap_set = CAPNG_SELECT_CAPS;

/**
 * This function will drop all capabilities.
 */
static int drop_caps(void)
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
 * If the user sends a siginto to seunshare, kill the child's session
 */
static void handler(int sig) {
	if (child > 0) kill(-child,sig);
}

/**
 * Take care of any signal setup.
 */
static int set_signal_handles(void)
{
	sigset_t empty;

	/* Empty the signal mask in case someone is blocking a signal */
	if (sigemptyset(&empty)) {
		fprintf(stderr, _("Unable to obtain empty signal set\n"));
		return -1;
	}

	(void)sigprocmask(SIG_SETMASK, &empty, NULL);

	/* Terminate on SIGHUP */
	if (signal(SIGHUP, SIG_DFL) == SIG_ERR) {
		perror(_("Unable to set SIGHUP handler"));
		return -1;
	}

	if (signal(SIGINT, handler) == SIG_ERR) {
		perror(_("Unable to set SIGINT handler"));
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
 * Spawn external command with dropped privileges.
 */
static int spawn_command(char **cmd, uid_t uid){
	int childpid;
	int status = -1;

	if (verbose > 1)
		printf("spawn_command: %s\n", cmd[0]);

	childpid = fork();
	if (childpid == -1) {
		perror(_("Unable to fork"));
		return status;
	}

	if (childpid == 0) {
		if (drop_privs(uid) != 0) exit(-1);

		status = execv(cmd[0], cmd);
		exit(status);
	}

	waitpid(childpid, &status, 0);
	status_to_retval(status, status);
	return status;
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
			rc = 0;
			break;
		}
	}
	endusershell();
	return rc;
}

/**
 * Mount directory and check that we mounted the right directory.
 */
static int seunshare_mount(const char *src, const char *dst, struct stat *src_st)
{
	int flags = 0;
	int is_tmp = 0;

	if (verbose)
		printf(_("Mounting %s on %s\n"), src, dst);

	if (strcmp("/tmp", dst) == 0) {
		flags = flags | MS_NODEV | MS_NOSUID | MS_NOEXEC;
		is_tmp = 1;
	}

	if (strncmp("/run/user", dst, 9) == 0) {
		flags = flags | MS_REC;
	}

	/* mount directory */
	if (mount(src, dst, NULL, MS_BIND | flags, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), src, dst, strerror(errno));
		return -1;
	}

	/* verify whether we mounted what we expected to mount */
	if (verify_directory(dst, src_st, NULL) < 0) return -1;

	/* bind mount /tmp on /var/tmp too */
	if (is_tmp) {
		if (verbose)
			printf(_("Mounting /tmp on /var/tmp\n"));

		if (mount("/tmp", "/var/tmp",  NULL, MS_BIND | flags, NULL) < 0) {
			fprintf(stderr, _("Failed to mount /tmp on /var/tmp: %s\n"), strerror(errno));
			return -1;
		}
	}

	return 0;

}

/**
 * Mount directory and check that we mounted the right directory.
 */
static int seunshare_mount_file(const char *src, const char *dst)
{
	int flags = 0;

	if (verbose)
		printf(_("Mounting %s on %s\n"), src, dst);

	if (access(dst, F_OK) == -1) {
		 FILE *fptr;
         fptr = fopen(dst, "w");
		 fclose(fptr);
	}
	/* mount file */
	if (mount(src, dst, NULL, MS_BIND | flags, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), src, dst, strerror(errno));
		return -1;
	}

	return 0;

}

/*
   If path is empty or ends with  "/." or "/.. return -1 else return 0;
 */
static int bad_path(const char *path) {
	const char *ptr;
	ptr = path;
	while (*ptr) ptr++;
	if (ptr == path) return -1; // ptr null
	ptr--;
	if (ptr != path && *ptr  == '.') {
		ptr--;
		if (*ptr  == '/') return -1; // path ends in /.
		if (*ptr  == '.') {
			if (ptr != path) {
				ptr--;
				if (*ptr  == '/') return -1; // path ends in /..
			}
		}
	}
	return 0;
}

static void free_args(char **args) {
	char **args_p = args;
	if (! args)
		return;
	while (*args_p != NULL) {
		free(*args_p);
		args_p++;
	}
	free(args);
}

static int rsynccmd(const char * src, const char *dst, char ***cmd) {
	char **args;
	char *buf = NULL;
	glob_t fglob;
	fglob.gl_offs = 0;
	int flags = GLOB_PERIOD;
	unsigned int i = 0, index;

	/* match glob for all files in src dir */
	if (asprintf(&buf, "%s/*", src) == -1) {
		fprintf(stderr, _("Out of memory\n"));
		return -1;
	}

	if (glob(buf, flags, NULL, &fglob) != 0) {
		free(buf); buf = NULL;
		return -1;
	}

	free(buf); buf = NULL;

	/* rsync  -trlHDq + <glob list> + dst + NULL */
	*cmd = calloc(2 + fglob.gl_pathc + 2, sizeof(char *));
	if (! *cmd) {
		fprintf(stderr, _("Out of memory\n"));
		return -1;
	}

	args = *cmd;
	strdup_or_err(args, 0, "/usr/bin/rsync");
	strdup_or_err(args, 1, "-trlHDq");

	for ( i=0, index = 2; i < fglob.gl_pathc; i++) {
		const char *path = fglob.gl_pathv[i];
		if (bad_path(path)) continue;
		strdup_or_err(args, index, path);
		index++;
	}
	strdup_or_err(args, index, dst);
	index++;
	args[index] = NULL;
	globfree(&fglob);
	return 0;
err:
	globfree(&fglob);
	if (args) {
		free_args(args);
		*cmd = NULL;
	}
	return -1;
}

/*
 * Recursively delete a directory.
 * SAFETY: This function will NOT follow symbolic links (AT_SYMLINK_NOFOLLOW).
 *         As a result, this function can be run safely on a directory owned by
 *         a non-root user: symbolic links to root paths (such as /root) will
 *         not be followed.
 */
static bool rm_rf(int targetfd, const char *path) {
	struct stat statbuf;

	if (fstatat(targetfd, path, &statbuf, AT_SYMLINK_NOFOLLOW) < 0) {
		if (errno == ENOENT) {
			return true;
		}
		perror("fstatat");
		return false;
	}

	if (S_ISDIR(statbuf.st_mode)) {
		const int newfd = openat(targetfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (newfd < 0) {
			perror("openat");
			return false;
		}

		DIR *dir = fdopendir(newfd);
		if (!dir) {
			perror("fdopendir");
			close(newfd);
			return false;
		}

		struct dirent *entry;
		int rc = true;
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
				continue;
			}

			if (!rm_rf(dirfd(dir), entry->d_name)) {
				rc = false;
			}
		}

		closedir(dir);

		if (unlinkat(targetfd, path, AT_REMOVEDIR) < 0) {
			perror("unlinkat");
			rc = false;
		}

		return rc;
	}
	if (unlinkat(targetfd, path, 0) < 0) {
		perror("unlinkat");
		return false;
	}
	return true;
}

/**
 * Clean up runtime temporary directory.  Returns 0 if no problem was detected,
 * >0 if some error was detected, but errors here are treated as non-fatal and
 * left to tmpwatch to finish incomplete cleanup.
 */
static int cleanup_tmpdir(const char *tmpdir, const char *src,
	struct passwd *pwd, int copy_content)
{
	char **args;
	int rc = 0;

	/* rsync files back */
	if (copy_content) {
		args = calloc(7, sizeof(char *));
		if (! args) {
			fprintf(stderr, _("Out of memory\n"));
			return 1;
		}

		strdup_or_err(args, 0, "/usr/bin/rsync");
		strdup_or_err(args, 1, "--exclude=.X11-unix");
		strdup_or_err(args, 2, "-utrlHDq");
		strdup_or_err(args, 3, "--delete");
		if (asprintf(&args[4], "%s/", tmpdir) == -1) {
			fprintf(stderr, _("Out of memory\n"));
			free_args(args);
			return 1;
		}
		if (asprintf(&args[5], "%s/", src) == -1) {
			fprintf(stderr, _("Out of memory\n"));
			free_args(args);
			return 1;
		}
		args[6] = NULL;

		if (spawn_command(args, pwd->pw_uid) != 0) {
			fprintf(stderr, _("Failed to copy files from the runtime temporary directory\n"));
			rc++;
		}
		free_args(args);
	}

	if ((uid_t)setfsuid(0) != 0) {
		/* setfsuid does not return error, but this check makes code checkers happy */
		rc++;
	}

	/* Recursively remove the runtime temp directory.  */
	if (!rm_rf(AT_FDCWD, tmpdir)) {
		fprintf(stderr, _("Failed to recursively remove directory %s\n"), tmpdir);
		rc++;
	}

	if ((uid_t)setfsuid(pwd->pw_uid) != 0) {
		fprintf(stderr, _("unable to switch back to user after clearing tmp dir\n"));
		rc++;
	}

	return rc;
err:
	if (args)
		free_args(args);
	return 1;
}

/**
 * seunshare will create a tmpdir in /tmp, with root ownership.  The parent
 * process waits for it child to exit to attempt to remove the directory.  If
 * it fails to remove the directory, we will need to rely on tmpreaper/tmpwatch
 * to clean it up.
 */
static char *create_tmpdir(const char *src, struct stat *src_st,
	struct stat *out_st, struct passwd *pwd, const char *execcon)
{
	char *tmpdir = NULL;
	char **cmd = NULL;
	int fd_t = -1, fd_s = -1;
	struct stat tmp_st;
	char *con = NULL;

	/* get selinux context */
	if (execcon) {
		if ((uid_t)setfsuid(pwd->pw_uid) != 0)
			goto err;

		if ((fd_s = open(src, O_RDONLY)) < 0) {
			fprintf(stderr, _("Failed to open directory %s: %s\n"), src, strerror(errno));
			goto err;
		}
		if (fstat(fd_s, &tmp_st) == -1) {
			fprintf(stderr, _("Failed to stat directory %s: %s\n"), src, strerror(errno));
			goto err;
		}
		if (!equal_stats(src_st, &tmp_st)) {
			fprintf(stderr, _("Error: %s was replaced by a different directory\n"), src);
			goto err;
		}
		if (fgetfilecon(fd_s, &con) == -1) {
			fprintf(stderr, _("Failed to get context of the directory %s: %s\n"), src, strerror(errno));
			goto err;
		}

		/* ok to not reach this if there is an error */
		if ((uid_t)setfsuid(0) != pwd->pw_uid)
			goto err;
	}

	if (asprintf(&tmpdir, "/tmp/.sandbox-%s-XXXXXX", pwd->pw_name) == -1) {
		fprintf(stderr, _("Out of memory\n"));
		tmpdir = NULL;
		goto err;
	}
	if (mkdtemp(tmpdir) == NULL) {
		fprintf(stderr, _("Failed to create temporary directory: %s\n"), strerror(errno));
		goto err;
	}

	/* temporary directory must be owned by root:user */
	if (verify_directory(tmpdir, NULL, out_st) < 0) {
		goto err;
	}

	if (check_owner_uid(0, tmpdir, out_st) < 0)
		goto err;

	if (check_owner_gid(getgid(), tmpdir, out_st) < 0)
		goto err;

	/* change permissions of the temporary directory */
	if ((fd_t = open(tmpdir, O_RDONLY)) < 0) {
		fprintf(stderr, _("Failed to open directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	if (fstat(fd_t, &tmp_st) == -1) {
		fprintf(stderr, _("Failed to stat directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	if (!equal_stats(out_st, &tmp_st)) {
		fprintf(stderr, _("Error: %s was replaced by a different directory\n"), tmpdir);
		goto err;
	}
	if (fchmod(fd_t, 01770) == -1) {
		fprintf(stderr, _("Unable to change mode on %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	/* re-stat again to pick change mode */
	if (fstat(fd_t, out_st) == -1) {
		fprintf(stderr, _("Failed to stat directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}

	/* copy selinux context */
	if (execcon) {
		if (fsetfilecon(fd_t, con) == -1) {
			fprintf(stderr, _("Failed to set context of the directory %s: %s\n"), tmpdir, strerror(errno));
			goto err;
		}
	}

	if ((uid_t)setfsuid(pwd->pw_uid) != 0)
		goto err;

	if (rsynccmd(src, tmpdir, &cmd) < 0) {
		goto err;
	}

	/* ok to not reach this if there is an error */
	if ((uid_t)setfsuid(0) != pwd->pw_uid)
		goto err;

	if (spawn_command(cmd, pwd->pw_uid) != 0) {
		fprintf(stderr, _("Failed to populate runtime temporary directory\n"));
		cleanup_tmpdir(tmpdir, src, pwd, 0);
		goto err;
	}

	goto good;
err:
	free(tmpdir); tmpdir = NULL;
good:
	free_args(cmd);
	freecon(con); con = NULL;
	if (fd_t >= 0) close(fd_t);
	if (fd_s >= 0) close(fd_s);
	return tmpdir;
}

#define PROC_BASE "/proc"

static int
killall (const char *execcon)
{
	DIR *dir;
	char *scon;
	struct dirent *de;
	pid_t *pid_table, pid, self;
	int i;
	int pids, max_pids;
	int running = 0;
	self = getpid();
	if (!(dir = opendir(PROC_BASE))) {
		return -1;
	}
	max_pids = 256;
	pid_table = malloc(max_pids * sizeof (pid_t));
	if (!pid_table) {
		(void)closedir(dir);
		return -1;
	}
	pids = 0;
	context_t con;
	con = context_new(execcon);
	const char *mcs = context_range_get(con);
	printf("mcs=%s\n", mcs);
	while ((de = readdir (dir)) != NULL) {
		if (!(pid = (pid_t)atoi(de->d_name)) || pid == self)
			continue;

		if (pids == max_pids) {
			pid_t *new_pid_table = realloc(pid_table, 2*pids*sizeof(pid_t));
			if (!new_pid_table) {
				free(pid_table);
				(void)closedir(dir);
				return -1;
			}
			pid_table = new_pid_table;
			max_pids *= 2;
		}
		pid_table[pids++] = pid;
	}

	(void)closedir(dir);

	for (i = 0; i < pids; i++) {
		pid_t id = pid_table[i];

		if (getpidcon(id, &scon) == 0) {

			context_t pidcon = context_new(scon);
			/* Attempt to kill remaining processes */
			if (strcmp(context_range_get(pidcon), mcs) == 0)
				kill(id, SIGKILL);

			context_free(pidcon);
			freecon(scon);
		}
		running++;
	}

	context_free(con);
	free(pid_table);
	return running;
}

int main(int argc, char **argv) {
	int status = -1;
	const char *execcon = NULL;
	const char *pipewire_socket = NULL;
	const char *wayland_display = NULL;

	int clflag;		/* holds codes for command line flags */
	int kill_all = 0;

	char *homedir_s = NULL;	/* homedir spec'd by user in argv[] */
	char *tmpdir_s = NULL;	/* tmpdir spec'd by user in argv[] */
	char *tmpdir_r = NULL;	/* tmpdir created by seunshare */
	char *runuserdir_s = NULL;	/* /var/run/user/UID spec'd by user in argv[] */
	char *runuserdir_r = NULL;	/* /var/run/user/UID created by seunshare */

	struct stat st_curhomedir;
	struct stat st_homedir;
	struct stat st_tmpdir_s;
	struct stat st_tmpdir_r;
	struct stat st_runuserdir_s;
	struct stat st_runuserdir_r;

	const struct option long_options[] = {
		{"homedir", 1, 0, 'h'},
		{"tmpdir", 1, 0, 't'},
		{"runuserdir", 1, 0, 'r'},
		{"kill", 1, 0, 'k'},
		{"verbose", 1, 0, 'v'},
		{"context", 1, 0, 'Z'},
		{"capabilities", 1, 0, 'C'},
		{"wayland", 1, 0, 'W'},
		{"pipewire", 1, 0, 'P'},
		{NULL, 0, 0, 0}
	};

	uid_t uid = getuid();
/*
	if (!uid) {
		fprintf(stderr, _("Must not be root"));
		return -1;
	}
*/

#ifdef USE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	struct passwd *pwd=getpwuid(uid);
	if (!pwd) {
		perror(_("getpwduid failed"));
		return -1;
	}

	if (verify_shell(pwd->pw_shell) < 0) {
		fprintf(stderr, _("Error: User shell is not valid\n"));
		return -1;
	}

	while (1) {
		clflag = getopt_long(argc, argv, "Ccvh:r:t:W:Z:", long_options, NULL);
		if (clflag == -1)
			break;

		switch (clflag) {
		case 't':
			tmpdir_s = optarg;
			break;
		case 'k':
			kill_all = 1;
			break;
		case 'h':
			homedir_s = optarg;
			break;
		case 'r':
			runuserdir_s = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'C':
			cap_set = CAPNG_SELECT_CAPS;
			break;
		case 'P':
			pipewire_socket = optarg;
			break;
		case 'W':
			wayland_display = optarg;
			break;
		case 'Z':
			execcon = optarg;
			break;
		default:
			fprintf(stderr, "%s\n", USAGE_STRING);
			return -1;
		}
	}

	if (! homedir_s && ! tmpdir_s) {
		fprintf(stderr, _("Error: tmpdir and/or homedir required\n %s\n"), USAGE_STRING);
		return -1;
	}

	if (argc - optind < 1) {
		fprintf(stderr, _("Error: executable required\n %s\n"), USAGE_STRING);
		return -1;
	}

	if (execcon && is_selinux_enabled() != 1) {
		fprintf(stderr, _("Error: execution context specified, but SELinux is not enabled\n"));
		return -1;
	}

	if (set_signal_handles())
		return -1;

	/* set fsuid to ruid */
	/* Changing fsuid is usually required when user-specified directory is
	 * on an NFS mount.  It's also desired to avoid leaking info about
	 * existence of the files not accessible to the user. */
	if (((uid_t)setfsuid(uid) != 0)   && (errno != 0)) {
		fprintf(stderr, _("Error: unable to setfsuid %m\n"));

		return -1;
	}

	/* verify homedir and tmpdir */
	if (homedir_s && (
		verify_directory(homedir_s, NULL, &st_homedir) < 0 ||
		check_owner_uid(uid, homedir_s, &st_homedir))) return -1;
	if (tmpdir_s && (
		verify_directory(tmpdir_s, NULL, &st_tmpdir_s) < 0 ||
		check_owner_uid(uid, tmpdir_s, &st_tmpdir_s))) return -1;
	if (runuserdir_s && (
		verify_directory(runuserdir_s, NULL, &st_runuserdir_s) < 0 ||
		check_owner_uid(uid, runuserdir_s, &st_runuserdir_s))) return -1;

	if ((uid_t)setfsuid(0) != uid) return -1;

	/* create runtime tmpdir */
	if (tmpdir_s && (tmpdir_r = create_tmpdir(tmpdir_s, &st_tmpdir_s,
						  &st_tmpdir_r, pwd, execcon)) == NULL) {
		fprintf(stderr, _("Failed to create runtime temporary directory\n"));
		return -1;
	}
	/* create runtime runuserdir */
	if (runuserdir_s && (runuserdir_r = create_tmpdir(runuserdir_s, &st_runuserdir_s,
						  &st_runuserdir_r, pwd, execcon)) == NULL) {
		fprintf(stderr, _("Failed to create runtime $XDG_RUNTIME_DIR directory\n"));
		return -1;
	}

	/* spawn child process */
	child = fork();
	if (child == -1) {
		perror(_("Unable to fork"));
		goto err;
	}

	if (child == 0) {
		char *display = NULL;
		char *LANG = NULL;
		char *RUNTIME_DIR = NULL;
		char *XDG_SESSION_TYPE = NULL;
		int rc = -1;
		char *resolved_path = NULL;
		char *wayland_path_s = NULL; /* /tmp/.../wayland-0 */
		char *wayland_path = NULL; /* /run/user/UID/wayland-0 */
		char *pipewire_path_s = NULL; /* /tmp/.../pipewire-0 */
		char *pipewire_path = NULL; /* /run/user/UID/pipewire-0 */


		if (unshare(CLONE_NEWNS) < 0) {
			perror(_("Failed to unshare"));
			goto childerr;
		}

		/* Remount / as SLAVE so that nothing mounted in the namespace 
		   shows up in the parent */
		if (mount("none", "/", NULL, MS_SLAVE | MS_REC , NULL) < 0) {
			perror(_("Failed to make / a SLAVE mountpoint\n"));
			goto childerr;
		}

		/* assume fsuid==ruid after this point */
		if ((uid_t)setfsuid(uid) != 0) goto childerr;

		resolved_path = realpath(pwd->pw_dir,NULL);
		if (! resolved_path) goto childerr;

		if (verify_directory(resolved_path, NULL, &st_curhomedir) < 0)
			goto childerr;
		if (check_owner_uid(uid, resolved_path, &st_curhomedir) < 0)
			goto childerr;

		if ((RUNTIME_DIR = getenv("XDG_RUNTIME_DIR")) != NULL) {
			if ((RUNTIME_DIR = strdup(RUNTIME_DIR)) == NULL) {
				perror(_("Out of memory"));
				goto childerr;
			}
		} else {
			if (asprintf(&RUNTIME_DIR, "/run/user/%d", uid) == -1) {
				perror(_("Out of memory\n"));
				goto childerr;
			}
		}

		if ((XDG_SESSION_TYPE = getenv("XDG_SESSION_TYPE")) != NULL) {
			if ((XDG_SESSION_TYPE = strdup(XDG_SESSION_TYPE)) == NULL) {
				perror(_("Out of memory"));
				goto childerr;
			}
		}

		if (runuserdir_s && (wayland_display || pipewire_socket)) {
			if (wayland_display) {
				if (asprintf(&wayland_path_s, "%s/%s", runuserdir_s, wayland_display) == -1) {
					perror(_("Out of memory"));
					goto childerr;
				}

				if (asprintf(&wayland_path, "%s/%s", RUNTIME_DIR, wayland_display) == -1) {
					perror(_("Out of memory"));
					goto childerr;
				}

				if (seunshare_mount_file(wayland_path, wayland_path_s) == -1)
					goto childerr;
			}

			if (pipewire_socket) {
				if (asprintf(&pipewire_path_s, "%s/%s", runuserdir_s, pipewire_socket) == -1) {
					perror(_("Out of memory"));
					goto childerr;
				}
				if (asprintf(&pipewire_path, "%s/pipewire-0", RUNTIME_DIR) == -1) {
					perror(_("Out of memory"));
					goto childerr;
				}
				seunshare_mount_file(pipewire_path, pipewire_path_s);
			}
		}

		/* mount homedir, runuserdir and tmpdir, in this order */
		if (runuserdir_s &&	seunshare_mount(runuserdir_s, RUNTIME_DIR,
			&st_runuserdir_s) != 0) goto childerr;
		if (homedir_s && seunshare_mount(homedir_s, resolved_path,
			&st_homedir) != 0) goto childerr;
		if (tmpdir_s &&	seunshare_mount(tmpdir_r, "/tmp",
			&st_tmpdir_r) != 0) goto childerr;

		if (drop_privs(uid) != 0) goto childerr;

		/* construct a new environment */

		if (XDG_SESSION_TYPE && strcmp(XDG_SESSION_TYPE, "wayland") == 0) {
			if (wayland_display == NULL && (wayland_display = getenv("WAYLAND_DISPLAY")) != NULL) {
				if ((wayland_display = strdup(wayland_display)) == NULL) {
					perror(_("Out of memory"));
					goto childerr;
				}
			}
		}
		else {
			if ((display = getenv("DISPLAY")) != NULL) {
				if ((display = strdup(display)) == NULL) {
					perror(_("Out of memory"));
					goto childerr;
				}
			}
		}

		/* construct a new environment */
		if ((LANG = getenv("LANG")) != NULL) {
			if ((LANG = strdup(LANG)) == NULL) {
				perror(_("Out of memory"));
				goto childerr;
			}
		}

		if ((rc = clearenv()) != 0) {
			perror(_("Failed to clear environment"));
			goto childerr;
		}
		if (display) {
			rc |= setenv("DISPLAY", display, 1);
		}
		if (wayland_display) {
			rc |= setenv("WAYLAND_DISPLAY", wayland_display, 1);
		}

		if (XDG_SESSION_TYPE)
			rc |= setenv("XDG_SESSION_TYPE", XDG_SESSION_TYPE, 1);

		if (LANG)
			rc |= setenv("LANG", LANG, 1);
		if (RUNTIME_DIR)
			rc |= setenv("XDG_RUNTIME_DIR", RUNTIME_DIR, 1);
		rc |= setenv("HOME", pwd->pw_dir, 1);
		rc |= setenv("SHELL", pwd->pw_shell, 1);
		rc |= setenv("USER", pwd->pw_name, 1);
		rc |= setenv("LOGNAME", pwd->pw_name, 1);
		rc |= setenv("PATH", DEFAULT_PATH, 1);
		if (rc != 0) {
			fprintf(stderr, _("Failed to construct environment\n"));
			goto childerr;
		}

		if (chdir(pwd->pw_dir)) {
			perror(_("Failed to change dir to homedir"));
			goto childerr;
		}
		setsid();

		/* selinux context */
		if (execcon) {
			/* try dyntransition, since no_new_privs can interfere
			 * with setexeccon */
			if (setcon(execcon) != 0) {
				/* failed; fall back to setexeccon */
				if (setexeccon(execcon) != 0) {
					fprintf(stderr, _("Could not set exec context to %s. %s\n"), execcon, strerror(errno));
					goto childerr;
				}
			}
		}

		execv(argv[optind], argv + optind);
		fprintf(stderr, _("Failed to execute command %s: %s\n"), argv[optind], strerror(errno));
childerr:
		free(resolved_path);
		free(wayland_path);
		free(wayland_path_s);
		free(pipewire_path);
		free(pipewire_path_s);
		free(display);
		free(LANG);
		free(RUNTIME_DIR);
		free(XDG_SESSION_TYPE);
		exit(-1);
	}

	drop_caps();

	/* parent waits for child exit to do the cleanup */
	waitpid(child, &status, 0);
	status_to_retval(status, status);

	/* Make sure all child processes exit */
	kill(-child,SIGTERM);

	if (execcon && kill_all)
		killall(execcon);

	if (tmpdir_r) cleanup_tmpdir(tmpdir_r, tmpdir_s, pwd, 1);

err:
	free(tmpdir_r);
	return status;
}
