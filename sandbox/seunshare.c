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

/**
 * Open directory with O_DIRECTORY|O_NOFOLLOW and return its fd
 * and fstat() results. The returned fd and its /proc/self/fd/N
 * path can be used for all subsequent operations on the directory.
 * NB Any non-final components in the @dir pathname are resolved
 * as usual but will be checked against the fsuid of the caller.
 */
static int pin_dir(const char *dir, struct stat *st_out)
{
	int fd;
	struct stat sb;

	fd = open(dir, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, _("Failed to open %s: %m\n"), dir);
		return -1;
	}

	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, _("Failed to stat %s: %m\n"), dir);
		close(fd);
		return -1;
	}

	if (st_out)
		*st_out = sb;
	return fd;
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
 * Bind-mount directory @src (using @src_fd) on directory @dst (using @dst_fd),
 * applying @bind_flags for the initial bind mount and @sec_flags if
 * non-zero via remount.
 */
static int seunshare_mount(const char *src, int src_fd,
			   const char *dst, int dst_fd,
			   int bind_flags, int sec_flags)
{
	char srcprocfd[32], dstprocfd[32];

	bind_flags |= MS_BIND;

	if (verbose)
		printf(_("Mounting %s on %s\n"), src, dst);

	snprintf(srcprocfd, sizeof(srcprocfd), "/proc/self/fd/%d", src_fd);
	snprintf(dstprocfd, sizeof(dstprocfd), "/proc/self/fd/%d", dst_fd);

	/* bind mount directory */
	if (mount(srcprocfd, dstprocfd, NULL, bind_flags, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %m\n"), src, dst);
		return -1;
	}

	/*
	 * Remount with security flags set - requires use of dst path again.
	 * Revisit when we migrate to open_tree()/move_mount().
	 */
	if (sec_flags &&
	    mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | sec_flags, NULL) < 0) {
		fprintf(stderr, _("Failed to remount %s: %m\n"), dst);
		return -1;
	}

	return 0;
}

/**
 * Bind-mount a file named @src_name in directory @src_dirfd on
 * a file named @dst_name in directory @dst_dirfd, creating @dst_name
 * if it doesn't already exist.
 */
static int seunshare_mount_file(uid_t uid, int src_dirfd, const char *src_name,
				int dst_dirfd, const char *dst_name)
{
	char srcprocfd[32], dstprocfd[32];
	int src_fd = -1, dst_fd = -1, rc = -1;
	struct stat sb;

	if (verbose)
		printf(_("Mounting %s on %s\n"), src_name, dst_name);

	src_fd = openat(src_dirfd, src_name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (src_fd < 0) {
		fprintf(stderr, _("Failed to open %s: %m\n"), src_name);
		goto out;
	}

	if (fstat(src_fd, &sb) < 0) {
		fprintf(stderr, _("Failed to stat %s: %m\n"), src_name);
		goto out;

	}
	if (check_owner_uid(uid, src_name, &sb))
		goto out;

	dst_fd = openat(dst_dirfd, dst_name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (dst_fd < 0 && errno == ENOENT)
		dst_fd = openat(dst_dirfd, dst_name,
				O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
				O_CLOEXEC, 0600);
	if (dst_fd < 0) {
		fprintf(stderr, _("Failed to open/create %s: %m\n"), dst_name);
		goto out;
	}

	if (fstat(dst_fd, &sb) < 0) {
		fprintf(stderr, _("Failed to stat %s: %m\n"), dst_name);
		goto out;

	}
	if (check_owner_uid(uid, dst_name, &sb))
		goto out;

	snprintf(srcprocfd, sizeof(srcprocfd), "/proc/self/fd/%d", src_fd);
	snprintf(dstprocfd, sizeof(dstprocfd), "/proc/self/fd/%d", dst_fd);

	/* mount file */
	if (mount(srcprocfd, dstprocfd, NULL, MS_BIND, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %m\n"), src_name,
			dst_name);
		goto out;
	}

	rc = 0;
out:
	if (src_fd >= 0)
		close(src_fd);
	if (dst_fd >= 0)
		close(dst_fd);
	return rc;
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

	/* rsync -trlHDq -- <glob list> dst NULL */
	*cmd = calloc(3 + fglob.gl_pathc + 2, sizeof(char *));
	if (! *cmd) {
		fprintf(stderr, _("Out of memory\n"));
		return -1;
	}

	args = *cmd;
	strdup_or_err(args, 0, "/usr/bin/rsync");
	strdup_or_err(args, 1, "-trlHDq");
	strdup_or_err(args, 2, "--");

	for ( i=0, index = 3; i < fglob.gl_pathc; i++) {
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
		const int newfd = openat(targetfd, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
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

/*
 * setfsuid() returns the previous fsuid value,
 * and does not reliably set errno on errors.
 * Let's do better.
 */
static int setfsuid_checked(uid_t old, uid_t new)
{
	int rc;

	rc = setfsuid(new);
	if ((uid_t)rc != old) {
		int save_errno = errno;
		fprintf(stderr,
			"setfsuid(%u): Returned unexpected old uid %u\n",
			new, (uid_t)rc);
		if (save_errno)
			errno = save_errno;
		else
			errno = EPERM;
		return -1;
	}

	rc = setfsuid(-1);
	if ((uid_t)rc != new) {
		int save_errno = errno;
		fprintf(stderr,
			"setfsuid(%u): Produced unexpected new uid %u\n",
			new,(uid_t)rc);
		if (save_errno)
			errno = save_errno;
		else
			errno = EPERM;
		return -1;
	}

	return 0;
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
		args = calloc(8, sizeof(char *));
		if (! args) {
			fprintf(stderr, _("Out of memory\n"));
			return 1;
		}

		strdup_or_err(args, 0, "/usr/bin/rsync");
		strdup_or_err(args, 1, "--exclude=.X11-unix");
		strdup_or_err(args, 2, "-utrlHDq");
		strdup_or_err(args, 3, "--delete");
		strdup_or_err(args, 4, "--");
		if (asprintf(&args[5], "%s/", tmpdir) == -1) {
			fprintf(stderr, _("Out of memory\n"));
			free_args(args);
			return 1;
		}
		if (asprintf(&args[6], "%s/", src) == -1) {
			fprintf(stderr, _("Out of memory\n"));
			free_args(args);
			return 1;
		}
		args[7] = NULL;

		if (spawn_command(args, pwd->pw_uid) != 0) {
			fprintf(stderr, _("Failed to copy files from the runtime temporary directory\n"));
			rc++;
		}
		free_args(args);
	}

	if (setfsuid_checked(0, 0) < 0)
		rc++;

	/* Recursively remove the runtime temp directory.  */
	if (!rm_rf(AT_FDCWD, tmpdir)) {
		fprintf(stderr, _("Failed to recursively remove directory %s\n"), tmpdir);
		rc++;
	}

	if (setfsuid_checked(0, pwd->pw_uid) < 0) {
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
			struct stat *out_st, struct passwd *pwd,
			const char *execcon)
{
	char *tmpdir = NULL;
	char **cmd = NULL;
	int fd_t = -1, fd_s = -1;
	struct stat tmp_st;
	char *con = NULL;

	/* get selinux context of source directory */
	if (execcon) {
		if (setfsuid_checked(0, pwd->pw_uid))
			goto err;
		if ((fd_s = pin_dir(src, &tmp_st)) < 0)
			goto err;
		if (tmp_st.st_dev != src_st->st_dev ||
		    tmp_st.st_ino != src_st->st_ino) {
			fprintf(stderr,
				_("%s was replaced by a different directory\n"),
				src);
			goto err;
		}
		if (fgetfilecon(fd_s, &con) == -1) {
			fprintf(stderr, _("Failed to get context of the directory %s: %m\n"), src);
			goto err;
		}
		if (setfsuid_checked(pwd->pw_uid, 0) < 0)
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
	fd_t = pin_dir(tmpdir, out_st);
	if (fd_t < 0)
		goto err;

	if (check_owner_uid(0, tmpdir, out_st) < 0)
		goto err;

	if (check_owner_gid(getgid(), tmpdir, out_st) < 0)
		goto err;

	/* change permissions of the temporary directory */
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

	if (setfsuid_checked(0, pwd->pw_uid) < 0)
		goto err;

	if (rsynccmd(src, tmpdir, &cmd) < 0) {
		goto err;
	}

	/* ok to not reach this if there is an error */
	if (setfsuid_checked(pwd->pw_uid, 0) < 0)
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
	if (fd_t >= 0) close(fd_t);
	if (fd_s >= 0) close(fd_s);
	free_args(cmd);
	freecon(con); con = NULL;
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
	unsigned int i;
	unsigned int pids, max_pids;
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
	context_t con = context_new(execcon);
	if (!con) {
		free(pid_table);
		(void)closedir(dir);
		return -1;
	}
	const char *const mcs = context_range_get(con);
	const char *const type = context_type_get(con);
	if (!mcs || !type) {
		context_free(con);
		free(pid_table);
		(void)closedir(dir);
		return -1;
	}
	if (verbose)
		printf("mcs=%s type=%s\n", mcs, type);
	while ((de = readdir (dir)) != NULL) {
		if (!(pid = (pid_t)atoi(de->d_name)) || pid == self)
			continue;

		if (pids == max_pids) {
			max_pids *= 2;
			if (max_pids <= pids)
			{
				free(pid_table);
				(void)closedir(dir);
				return -1;
			}
			pid_t *new_pid_table = reallocarray(pid_table, max_pids, sizeof(pid_t));
			if (!new_pid_table) {
				free(pid_table);
				(void)closedir(dir);
				return -1;
			}
			pid_table = new_pid_table;
		}
		pid_table[pids++] = pid;
	}

	(void)closedir(dir);

	for (i = 0; i < pids; i++) {
		pid_t id = pid_table[i];

		if (getpidcon(id, &scon) == 0) {

			context_t pidcon = context_new(scon);
			if (pidcon) {
				const char *const pmcs = context_range_get(pidcon);
				const char *const ptype = context_type_get(pidcon);

				/* Attempt to kill remaining processes */
				if (pmcs && ptype && !strcmp(pmcs, mcs) &&
					!strcmp(ptype, type))
					kill(id, SIGKILL);

				context_free(pidcon);
			}
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

	struct stat st_homedir;
	struct stat st_tmpdir_s;
	struct stat st_tmpdir_r;
	struct stat st_runuserdir_s;

	int fd;

	const struct option long_options[] = {
		{"homedir", 1, 0, 'h'},
		{"tmpdir", 1, 0, 't'},
		{"runuserdir", 1, 0, 'r'},
		{"kill", 0, 0, 'k'},
		{"verbose", 0, 0, 'v'},
		{"context", 1, 0, 'Z'},
		{"capabilities", 0, 0, 'C'},
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
		clflag = getopt_long(argc, argv, "Ckvh:r:t:W:P:Z:", long_options, NULL);
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

	if ((wayland_display && (strchr(wayland_display, '/') || strstr(wayland_display, ".."))) ||
		(pipewire_socket && (strchr(pipewire_socket, '/') || strstr(pipewire_socket, "..")))) {
		fprintf(stderr, _("Error: -W/-P must be a socket name, not a path\n"));
		return -1;
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
	if (setfsuid_checked(0, uid) < 0) {
		fprintf(stderr, _("Error: unable to setfsuid\n"));
		return -1;
	}

	/*
	 * Perform early validation of the caller-provided directories so we
	 * can fail fast, but we unfortunately have to redo this after
	 * unsharing the mount namespace in the child so that it can use
	 * the descriptors for subsequent mount(2) calls. Otherwise,
	 * they end up with a different mount namespace and mount(2) fails
	 * with errno EINVAL.
	 */
	if (homedir_s) {
		fd = pin_dir(homedir_s, &st_homedir);
		if (fd < 0)
			return -1;
		if (check_owner_uid(uid, homedir_s, &st_homedir))
			return -1;
		close(fd);
	}
	if (tmpdir_s) {
		fd = pin_dir(tmpdir_s, &st_tmpdir_s);
		if (fd < 0)
			return -1;
		if (check_owner_uid(uid, tmpdir_s, &st_tmpdir_s))
			return -1;
		close(fd);
	}
	if (runuserdir_s) {
		fd = pin_dir(runuserdir_s, &st_runuserdir_s);
		if (fd < 0)
			return -1;
		if (check_owner_uid(uid, runuserdir_s, &st_runuserdir_s))
			return -1;
		close(fd);
	}

	if (setfsuid_checked(uid, 0) < 0)
		return -1;

	/* create runtime tmpdir */
	if (tmpdir_s) {
		tmpdir_r = create_tmpdir(tmpdir_s, &st_tmpdir_s, &st_tmpdir_r,
					 pwd, execcon);
		if (!tmpdir_r) {
			fprintf(stderr, _("Failed to create runtime temporary directory\n"));
			return -1;
		}
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
		int fd_homedir_s = -1, fd_curhomedir = -1;
		int fd_runuserdir_s = -1, fd_runtime_dir = -1;
		int fd_tmpdir_r = -1, fd_tmp = -1, fd_var_tmp = -1;
		struct stat sb;

		if (unshare(CLONE_NEWNS) < 0) {
			perror(_("Failed to unshare"));
			goto childerr;
		}

		/* Remount / as SLAVE so that nothing mounted in the namespace 
		   shows up in the parent */
		if (mount("none", "/", NULL, MS_SLAVE | MS_REC , NULL) < 0) {

			goto childerr;
		}

		/* assume fsuid==ruid after this point */
		if (setfsuid_checked(0, uid) < 0) goto childerr;

		/*
		 * Now we can pin the source directories in this namespace
		 * for later use by mount(2). We recheck that each
		 * directory is the same inode and still has the
		 * expected ownership as the early validation.
		 */
		if (homedir_s) {
			fd_homedir_s = pin_dir(homedir_s, &sb);
			if (fd_homedir_s < 0)
				goto childerr;
			if (sb.st_dev != st_homedir.st_dev ||
				sb.st_ino != st_homedir.st_ino)
				goto childerr;
			if (check_owner_uid(uid, homedir_s, &sb))
				goto childerr;
		}
		/*
		 * NB We don't need to re-pin tmpdir_s, just tmpdir_r,
		 * since the child never uses tmpdir_s.
		 */
		if (tmpdir_r) {
			fd_tmpdir_r = pin_dir(tmpdir_r, &sb);
			if (fd_tmpdir_r < 0)
				goto childerr;
			/*
			 * tmpdir_r checks differ in that it is
			 * root-owned and we also want to validate
			 * that the mode is still correct.
			 */
			if (sb.st_dev != st_tmpdir_r.st_dev ||
				sb.st_ino != st_tmpdir_r.st_ino ||
				sb.st_mode != st_tmpdir_r.st_mode)
				goto childerr;
			if (check_owner_uid(0, tmpdir_r, &sb))
				goto childerr;
		}
		if (runuserdir_s) {
			fd_runuserdir_s = pin_dir(runuserdir_s, &sb);
			if (fd_runuserdir_s < 0)
				goto childerr;
			if (sb.st_dev != st_runuserdir_s.st_dev ||
				sb.st_ino != st_runuserdir_s.st_ino)
				goto childerr;
			if (check_owner_uid(uid, runuserdir_s, &sb))
				goto childerr;
		}

		resolved_path = realpath(pwd->pw_dir,NULL);
		if (! resolved_path) goto childerr;

		fd_curhomedir = pin_dir(resolved_path, &sb);
		if (fd_curhomedir < 0)
			goto childerr;
		if (check_owner_uid(uid, resolved_path, &sb) < 0)
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

		if (runuserdir_s) {
			fd_runtime_dir = pin_dir(RUNTIME_DIR, &sb);
			if (fd_runtime_dir < 0)
				goto childerr;
			if (check_owner_uid(uid, RUNTIME_DIR, &sb) < 0)
				goto childerr;
		}

		if ((XDG_SESSION_TYPE = getenv("XDG_SESSION_TYPE")) != NULL) {
			if ((XDG_SESSION_TYPE = strdup(XDG_SESSION_TYPE)) == NULL) {
				perror(_("Out of memory"));
				goto childerr;
			}
		}

		if (runuserdir_s && (wayland_display || pipewire_socket)) {
			if (wayland_display &&
				seunshare_mount_file(uid, fd_runtime_dir,
					    wayland_display,
					    fd_runuserdir_s,
					    wayland_display) == -1)
					goto childerr;

			if (pipewire_socket &&
				seunshare_mount_file(uid, fd_runtime_dir,
					    "pipewire-0",
					    fd_runuserdir_s,
					    pipewire_socket) == -1)
				goto childerr;
		}

		/* mount homedir, runuserdir and tmpdir, in this order */
		if (runuserdir_s &&
			seunshare_mount(runuserdir_s, fd_runuserdir_s,
					RUNTIME_DIR, fd_runtime_dir,
					MS_REC, 0) != 0)
			goto childerr;
		if (homedir_s &&
			seunshare_mount(homedir_s, fd_homedir_s,
					resolved_path, fd_curhomedir,
					0, 0) != 0)
			goto childerr;
		if (tmpdir_s) {
			fd_tmp = open("/tmp", O_RDONLY | O_DIRECTORY |
				      O_NOFOLLOW | O_CLOEXEC);
			if (fd_tmp < 0) {
				perror(_("Failed to open /tmp"));
				goto childerr;
			}

			if (seunshare_mount(tmpdir_r, fd_tmpdir_r,
					    "/tmp", fd_tmp, 0,
					    MS_NODEV|MS_NOSUID|MS_NOEXEC) < 0)
				goto childerr;

			fd_var_tmp = open("/var/tmp", O_RDONLY | O_DIRECTORY |
					O_NOFOLLOW | O_CLOEXEC);
			if (fd_var_tmp < 0) {
				perror(_("Failed to open /var/tmp"));
				goto childerr;
			}

			if (seunshare_mount("/tmp", fd_tmpdir_r,
					"/var/tmp", fd_var_tmp, 0,
					MS_NODEV|MS_NOSUID|MS_NOEXEC) < 0)
				goto childerr;
		}

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
		if (fd_homedir_s >= 0) close(fd_homedir_s);
		if (fd_curhomedir >= 0) close(fd_curhomedir);
		if (fd_runuserdir_s >= 0) close(fd_runuserdir_s);
		if (fd_runtime_dir >= 0) close(fd_runtime_dir);
		if (fd_tmpdir_r >= 0) close(fd_tmpdir_r);
		if (fd_tmp >= 0) close(fd_tmp);
		if (fd_var_tmp >= 0) close(fd_var_tmp);
		free(resolved_path);
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
