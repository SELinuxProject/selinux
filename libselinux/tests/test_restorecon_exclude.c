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
static bool deny_read;
static unsigned int read_attempts, target_labels, other_labels;

static bool is_target(const struct stat *sb)
{
	return sb->st_ino == target_ino && sb->st_dev == target_dev;
}

/* Only the directory read-open is fault-injected; O_PATH pinning is real. */
#define WRAP_OPENAT(name)                                             \
	int __real_##name(int fd, const char *path, int flags, ...);  \
	int __wrap_##name(int fd, const char *path, int flags, ...);  \
	int __wrap_##name(int fd, const char *path, int flags, ...)   \
	{                                                             \
		assert(!(flags & O_CREAT));                           \
		if (!(flags & O_PATH) && !strcmp(path, ".")) {        \
			struct stat sb;                               \
			assert(fstat(fd, &sb) == 0);                  \
			if (is_target(&sb)) {                         \
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
	if (is_target(&sb))
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

static void run_case(bool root_case, bool exclude, bool denied,
		     unsigned int mode, size_t threads)
{
	char root[] = "/tmp/restorecon-exclude-XXXXXX";
	char target[256], sibling[256], fc[256];
	struct stat sb;
	alarm(15);
	assert(mkdtemp(root));
	assert(snprintf(target, sizeof(target), "%s/target", root) > 0);
	assert(snprintf(sibling, sizeof(sibling), "%s/sibling", root) > 0);
	assert(snprintf(fc, sizeof(fc), "%s.fc", root) > 0);
	assert(mkdir(target, 0700) == 0);
	int fd = open(sibling, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	assert(stat(target, &sb) == 0);
	target_ino = sb.st_ino;
	target_dev = sb.st_dev;
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
	const char *excluded[] = { target, NULL };
	if (exclude)
		selinux_restorecon_set_exclude_list(excluded);
	unsigned int flags = SELINUX_RESTORECON_RECURSE |
			     SELINUX_RESTORECON_IGNORE_MOUNTS |
			     SELINUX_RESTORECON_NOCHANGE |
			     SELINUX_RESTORECON_SET_SPECFILE_CTX | mode;
	int rc = selinux_restorecon_parallel(root_case ? target : root, flags,
					     threads);
	bool failure = denied && !exclude;
	assert(rc ==
	       (failure && mode != SELINUX_RESTORECON_COUNT_ERRORS ? -1 : 0));
	assert(read_attempts == (exclude ? 0 : 1));
	if (exclude) {
		assert(target_labels == 0);
		assert(selinux_restorecon_get_skipped_errors() == 0);
	}
	if (!failure) {
		assert(target_labels == (exclude ? 0 : 1));
		assert(other_labels == (root_case ? 0 : 2));
	}
	assert(unlink(sibling) == 0 && rmdir(target) == 0);
	assert(rmdir(root) == 0 && unlink(fc) == 0);
	selinux_restorecon_set_sehandle(NULL);
}

int main(void)
{
	const size_t threads[] = { 1, 2, 8 };
	const unsigned int modes[] = { 0, SELINUX_RESTORECON_COUNT_ERRORS,
				       SELINUX_RESTORECON_ABORT_ON_ERROR };
	unsigned int cases = 0;
	for (int root = 0; root < 2; root++)
		for (int exclude = 0; exclude < 2; exclude++)
			for (int deny = 0; deny < 2; deny++)
				for (size_t m = 0; m < 3; m++)
					for (size_t t = 0; t < 3; t++) {
						pid_t pid = fork();
						int status;
						assert(pid >= 0);
						if (!pid) {
							run_case(root, exclude,
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
	printf("Restorecon exclusions: %u cases passed.\n", cases);
	return 0;
}
