/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

static ino_t target_ino;
static dev_t target_dev;
static bool foreign_device, deny_read;
static unsigned int read_attempts, target_labels, other_labels;

/* Simulate a mount boundary without requiring mount privileges. */
#define WRAP_STAT(name, type)                                            \
	int __real_##name(int fd, struct type *sb);                      \
	int __wrap_##name(int fd, struct type *sb);                      \
	int __wrap_##name(int fd, struct type *sb)                       \
	{                                                                \
		int rc = __real_##name(fd, sb);                          \
		if (!rc && foreign_device && sb->st_ino == target_ino && \
		    sb->st_dev == target_dev)                            \
			sb->st_dev ^= 1;                                 \
		return rc;                                               \
	}
WRAP_STAT(fstat, stat)
WRAP_STAT(fstat64, stat64)

/* The pinned inode remains real; only its read-open can be denied. */
#define WRAP_OPENAT(name)                                             \
	int __real_##name(int fd, const char *path, int flags, ...);  \
	int __wrap_##name(int fd, const char *path, int flags, ...);  \
	int __wrap_##name(int fd, const char *path, int flags, ...)   \
	{                                                             \
		assert(!(flags & O_CREAT));                           \
		if (!(flags & O_PATH) && !strcmp(path, ".")) {        \
			struct stat sb;                               \
			assert(__real_fstat(fd, &sb) == 0);           \
			if (sb.st_ino == target_ino &&                \
			    sb.st_dev == target_dev) {                \
				__atomic_add_fetch(&read_attempts, 1, \
						   __ATOMIC_RELAXED); \
				if (deny_read) {                      \
					errno = EACCES;               \
					return -1;                    \
				}                                     \
			}                                             \
		}                                                     \
		return __real_##name(fd, path, flags);                \
	}
WRAP_OPENAT(openat)
WRAP_OPENAT(openat64)

int __wrap_getfilecon_raw(const char *path, char **context);
int __wrap_lgetfilecon_raw(const char *path, char **context);

int __wrap_getfilecon_raw(const char *path, char **context)
{
	struct stat sb;
	assert(stat(path, &sb) == 0);
	if (sb.st_ino == target_ino && sb.st_dev == target_dev)
		__atomic_add_fetch(&target_labels, 1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&other_labels, 1, __ATOMIC_RELAXED);
	*context = NULL;
	errno = ENODATA;
	return -1;
}

int __wrap_lgetfilecon_raw(const char *path, char **context)
{
	return __wrap_getfilecon_raw(path, context);
}

static void run_case(bool foreign, bool xdev, bool denied, unsigned int mode,
		     size_t threads)
{
	char root[] = "/tmp/restorecon-xdev-XXXXXX";
	char target[256], child[256], sibling[256], fc[256];
	struct stat sb;
	alarm(15);
	assert(mkdtemp(root));
	assert(snprintf(target, sizeof(target), "%s/target", root) > 0);
	assert(snprintf(child, sizeof(child), "%s/target/child", root) > 0);
	assert(snprintf(sibling, sizeof(sibling), "%s/sibling", root) > 0);
	assert(snprintf(fc, sizeof(fc), "%s.fc", root) > 0);
	assert(mkdir(target, 0700) == 0);
	int fd = open(sibling, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	fd = open(child, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	assert(stat(target, &sb) == 0);
	target_ino = sb.st_ino;
	target_dev = sb.st_dev;
	foreign_device = foreign;
	deny_read = denied;
	FILE *fp = fopen(fc, "w");
	assert(fp);
	assert(fprintf(fp, "%s(/.*)? system_u:object_r:test_t:s0\n", root) > 0);
	assert(fclose(fp) == 0);
	struct selinux_opt option = { SELABEL_OPT_PATH, fc };
	struct selabel_handle *handle =
		selabel_open(SELABEL_CTX_FILE, &option, 1);
	assert(handle);
	selinux_restorecon_set_sehandle(handle);
	unsigned int flags = SELINUX_RESTORECON_RECURSE |
			     SELINUX_RESTORECON_IGNORE_MOUNTS |
			     SELINUX_RESTORECON_NOCHANGE |
			     SELINUX_RESTORECON_SET_SPECFILE_CTX | mode;
	if (xdev)
		flags |= SELINUX_RESTORECON_XDEV;
	int rc = selinux_restorecon_parallel(root, flags, threads);
	bool skip = foreign && xdev;
	bool failure = denied && !skip;
	assert(rc ==
	       (failure && mode != SELINUX_RESTORECON_COUNT_ERRORS ? -1 : 0));
	assert(read_attempts == (skip ? 0 : 1));
	if (skip) {
		assert(target_labels == 0 && other_labels == 2);
		assert(selinux_restorecon_get_skipped_errors() == 0);
	} else if (!failure || mode != SELINUX_RESTORECON_ABORT_ON_ERROR) {
		assert(target_labels == 1);
		assert(other_labels == (denied ? 2 : 3));
	}
	assert(unlink(child) == 0 && unlink(sibling) == 0);
	assert(rmdir(target) == 0 && rmdir(root) == 0 && unlink(fc) == 0);
	selinux_restorecon_set_sehandle(NULL);
}

int main(void)
{
	const size_t threads[] = { 1, 2, 8 };
	const unsigned int modes[] = { 0, SELINUX_RESTORECON_COUNT_ERRORS,
				       SELINUX_RESTORECON_ABORT_ON_ERROR };
	unsigned int cases = 0;
	for (int foreign = 0; foreign < 2; foreign++)
		for (int xdev = 0; xdev < 2; xdev++)
			for (int deny = 0; deny < 2; deny++)
				for (size_t m = 0; m < 3; m++)
					for (size_t t = 0; t < 3; t++) {
						pid_t pid = fork();
						int status;
						assert(pid >= 0);
						if (!pid) {
							run_case(foreign, xdev,
								 deny, modes[m],
								 threads[t]);
							_exit(0);
						}
						assert(waitpid(pid, &status,
							       0) == pid);
						assert(WIFEXITED(status) &&
						       WEXITSTATUS(status) ==
							       0);
						cases++;
					}
	printf("Restorecon XDEV: %u cases passed.\n", cases);
	return 0;
}
