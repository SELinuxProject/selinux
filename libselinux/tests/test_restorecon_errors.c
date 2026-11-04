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

static int label_errno;
static unsigned int attempts;

int __wrap_getfilecon_raw(const char *path, char **context);
int __wrap_lgetfilecon_raw(const char *path, char **context);
int __wrap_setfilecon_raw(const char *path, const char *context);
int __wrap_lsetfilecon_raw(const char *path, const char *context);

int __wrap_getfilecon_raw(const char *path, char **context)
{
	(void)path;
	*context = NULL;
	errno = ENODATA;
	return -1;
}

int __wrap_lgetfilecon_raw(const char *path, char **context)
{
	return __wrap_getfilecon_raw(path, context);
}

int __wrap_setfilecon_raw(const char *path, const char *context)
{
	struct stat sb;
	(void)context;
	assert(stat(path, &sb) == 0);
	if (S_ISREG(sb.st_mode)) {
		__atomic_add_fetch(&attempts, 1, __ATOMIC_RELAXED);
		if (label_errno) {
			errno = label_errno;
			return -1;
		}
	}
	/* A successful operation need not clear errno. */
	errno = ENODATA;
	return 0;
}

int __wrap_lsetfilecon_raw(const char *path, const char *context)
{
	return __wrap_setfilecon_raw(path, context);
}

enum test_case {
	FAILED_FILE,
	FAILED_DIRECTORY,
	SUCCESS_FILE,
	SUCCESS_DIRECTORY,
	MISSING_FILE,
	MISSING_REALPATH_FILE,
	MISSING_REALPATH_PARENT,
	EXCLUDED_FILE,
	NONRECURSIVE_FILE,
	IGNORED_LABEL_ERROR,
	ABORT_ERROR,
	UNCOUNTED_ERROR,
	CASE_COUNT
};

static void run_case(size_t threads, enum test_case test)
{
	char root[] = "/tmp/restorecon-errors-XXXXXX";
	char file[256], fc[256], missing[256], missing_parent[256];
	unsigned int flags = SELINUX_RESTORECON_RECURSE |
			     SELINUX_RESTORECON_IGNORE_MOUNTS |
			     SELINUX_RESTORECON_SET_SPECFILE_CTX |
			     SELINUX_RESTORECON_COUNT_ERRORS;
	unsigned long expected = 0;
	int expected_rc = 0;
	unsigned int expected_attempts = 1;
	const char *path = file;

	alarm(15);
	assert(mkdtemp(root));
	assert(snprintf(file, sizeof(file), "%s/child", root) > 0);
	assert(snprintf(fc, sizeof(fc), "%s.fc", root) > 0);
	assert(snprintf(missing, sizeof(missing), "%s/missing", root) > 0);
	assert(snprintf(missing_parent, sizeof(missing_parent),
			"%s/missing/child", root) > 0);
	int fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	FILE *fp = fopen(fc, "w");
	assert(fp);
	assert(fprintf(fp, "%s(/.*)? system_u:object_r:test_t:s0\n", root) > 0);
	assert(fclose(fp) == 0);
	struct selinux_opt option = { SELABEL_OPT_PATH, fc };
	struct selabel_handle *handle =
		selabel_open(SELABEL_CTX_FILE, &option, 1);
	assert(handle);
	selinux_restorecon_set_sehandle(handle);

	if (test >= SUCCESS_FILE) {
		/* Seed a nonzero count without depending on the root-file fix. */
		label_errno = EACCES;
		assert(selinux_restorecon(root, flags) == 0);
		assert(selinux_restorecon_get_skipped_errors() == 1);
		label_errno = 0;
		attempts = 0;
	}
	switch (test) {
	case FAILED_DIRECTORY:
		path = root;
		/* fall through */
	case FAILED_FILE:
		label_errno = EACCES;
		expected = 1;
		break;
	case SUCCESS_FILE:
		break;
	case SUCCESS_DIRECTORY:
		path = root;
		break;
	case MISSING_REALPATH_PARENT:
		path = missing_parent;
		flags |= SELINUX_RESTORECON_REALPATH;
		flags |= SELINUX_RESTORECON_IGNORE_NOENTRY;
		expected_attempts = 0;
		break;
	case MISSING_REALPATH_FILE:
		flags |= SELINUX_RESTORECON_REALPATH;
		/* fall through */
	case MISSING_FILE:
		path = missing;
		flags |= SELINUX_RESTORECON_IGNORE_NOENTRY;
		expected_attempts = 0;
		break;
	case EXCLUDED_FILE: {
		const char *excludes[] = { file, NULL };
		selinux_restorecon_set_exclude_list(excludes);
		flags &= ~SELINUX_RESTORECON_RECURSE;
		expected_attempts = 0;
		break;
	}
	case NONRECURSIVE_FILE:
		flags &= ~SELINUX_RESTORECON_RECURSE;
		break;
	case IGNORED_LABEL_ERROR:
		label_errno = ENOENT;
		flags |= SELINUX_RESTORECON_IGNORE_NOENTRY;
		break;
	case ABORT_ERROR:
		flags |= SELINUX_RESTORECON_ABORT_ON_ERROR;
		label_errno = EACCES;
		expected_rc = -1;
		break;
	case UNCOUNTED_ERROR:
		flags &= ~SELINUX_RESTORECON_COUNT_ERRORS;
		label_errno = EACCES;
		expected_rc = -1;
		break;
	case CASE_COUNT:
		abort();
	}
	int rc = threads == 1 ?
			 selinux_restorecon(path, flags) :
			 selinux_restorecon_parallel(path, flags, threads);
	assert(rc == expected_rc);
	assert(attempts == expected_attempts);
	if (!rc)
		assert(selinux_restorecon_get_skipped_errors() == expected);
	assert(unlink(file) == 0 && rmdir(root) == 0 && unlink(fc) == 0);
	selinux_restorecon_set_sehandle(NULL);
}

int main(int argc, char **argv)
{
	const size_t threads[] = { 1, 2, 8 };
	unsigned int cases = 0;
	for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); i++) {
		for (int test = 0; test < CASE_COUNT; test++) {
			if (argc > 1 && test != atoi(argv[1]))
				continue;
			pid_t pid = fork();
			int status;
			assert(pid >= 0);
			if (!pid) {
				run_case(threads[i], test);
				_exit(0);
			}
			assert(waitpid(pid, &status, 0) == pid);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			cases++;
		}
	}
	printf("Restorecon error counts: %u cases passed.\n", cases);
	return 0;
}
