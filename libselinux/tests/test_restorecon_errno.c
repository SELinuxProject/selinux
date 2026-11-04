/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

enum fault {
	LABEL_WRITE,
	LABEL_READ,
	DIRECTORY_READ,
	DIRECTORY_STREAM,
	FILESYSTEM_STAT,
	DIRECTORY_OPEN,
	CHILD_OPEN,
	MISSING_ROOT,
	ROOT_STAT,
	CHILD_STAT,
	STACK_ALLOC,
	FAULT_COUNT
};

static enum fault fault;
static bool inject, clobber;
static unsigned int hits;

static bool fail(enum fault at)
{
	if (!inject || fault != at)
		return false;
	__atomic_add_fetch(&hits, 1, __ATOMIC_RELAXED);
	return true;
}

int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_close(int fd)
{
	int rc = __real_close(fd);
	if (clobber)
		errno = EBADF;
	return rc;
}

int __real_closedir(DIR *dir);
int __wrap_closedir(DIR *dir);
int __wrap_closedir(DIR *dir)
{
	int rc = __real_closedir(dir);
	if (clobber)
		errno = EBADF;
	return rc;
}

DIR *__real_fdopendir(int fd);
DIR *__wrap_fdopendir(int fd);
DIR *__wrap_fdopendir(int fd)
{
	if (fail(DIRECTORY_STREAM)) {
		errno = EMFILE;
		return NULL;
	}
	return __real_fdopendir(fd);
}

#define WRAP_READDIR(name, type)            \
	type *__real_##name(DIR *dir);      \
	type *__wrap_##name(DIR *dir);      \
	type *__wrap_##name(DIR *dir)       \
	{                                   \
		if (fail(DIRECTORY_READ)) { \
			errno = EIO;        \
			return NULL;        \
		}                           \
		return __real_##name(dir);  \
	}
WRAP_READDIR(readdir, struct dirent)
WRAP_READDIR(readdir64, struct dirent64)

#define WRAP_STATFS(name, type)                \
	int __real_##name(int fd, type *buf);  \
	int __wrap_##name(int fd, type *buf);  \
	int __wrap_##name(int fd, type *buf)   \
	{                                      \
		if (fail(FILESYSTEM_STAT)) {   \
			errno = EIO;           \
			return -1;             \
		}                              \
		return __real_##name(fd, buf); \
	}
WRAP_STATFS(fstatfs, struct statfs)
WRAP_STATFS(fstatfs64, struct statfs64)

#define WRAP_STAT(name, type)                                               \
	int __real_##name(int fd, type *buf);                               \
	int __wrap_##name(int fd, type *buf);                               \
	int __wrap_##name(int fd, type *buf)                                \
	{                                                                   \
		int rc = __real_##name(fd, buf);                            \
		if (!rc && ((S_ISDIR(buf->st_mode) && fail(ROOT_STAT)) ||   \
			    (S_ISREG(buf->st_mode) && fail(CHILD_STAT)))) { \
			errno = EOVERFLOW;                                  \
			return -1;                                          \
		}                                                           \
		return rc;                                                  \
	}
WRAP_STAT(fstat, struct stat)
WRAP_STAT(fstat64, struct stat64)

void *__real_reallocarray(void *ptr, size_t n, size_t size);
void *__wrap_reallocarray(void *ptr, size_t n, size_t size);
void *__wrap_reallocarray(void *ptr, size_t n, size_t size)
{
	if (fail(STACK_ALLOC)) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_reallocarray(ptr, n, size);
}

/* Restorecon opens only existing paths; neither variant needs a mode. */
#define WRAP_OPENAT(name)                                            \
	int __real_##name(int fd, const char *path, int flags, ...); \
	int __wrap_##name(int fd, const char *path, int flags, ...); \
	int __wrap_##name(int fd, const char *path, int flags, ...)  \
	{                                                            \
		assert(!(flags & O_CREAT));                          \
		if ((!strcmp(path, ".") && fail(DIRECTORY_OPEN)) ||  \
		    (!strcmp(path, "child") && fail(CHILD_OPEN))) {  \
			errno = EACCES;                              \
			return -1;                                   \
		}                                                    \
		return __real_##name(fd, path, flags);               \
	}
WRAP_OPENAT(openat)
WRAP_OPENAT(openat64)

int __wrap_getfilecon_raw(const char *path, char **context);
int __wrap_lgetfilecon_raw(const char *path, char **context);
int __wrap_setfilecon_raw(const char *path, const char *context);
int __wrap_lsetfilecon_raw(const char *path, const char *context);

int __wrap_getfilecon_raw(const char *path, char **context)
{
	struct stat sb;
	assert(stat(path, &sb) == 0);
	*context = NULL;
	if (S_ISREG(sb.st_mode) && fail(LABEL_READ)) {
		errno = EACCES;
		return -1;
	}
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
	if (S_ISREG(sb.st_mode) && fail(LABEL_WRITE)) {
		errno = ENOSPC;
		return -1;
	}
	errno = ENODATA;
	return 0;
}

int __wrap_lsetfilecon_raw(const char *path, const char *context)
{
	return __wrap_setfilecon_raw(path, context);
}

static void run_case(size_t threads, enum fault at, unsigned int extra,
		     bool overwrite)
{
	char root[] = "/tmp/restorecon-errno-XXXXXX";
	char file[256], fc[256], missing[256];
	const int errors[] = { ENOSPC,	  EACCES,    EIO,    EMFILE,
			       EIO,	  EACCES,    EACCES, ENOENT,
			       EOVERFLOW, EOVERFLOW, ENOMEM };
	unsigned int flags = SELINUX_RESTORECON_RECURSE |
			     SELINUX_RESTORECON_IGNORE_MOUNTS |
			     SELINUX_RESTORECON_SET_SPECFILE_CTX |
			     SELINUX_RESTORECON_XDEV | extra;
	bool counted = extra == SELINUX_RESTORECON_COUNT_ERRORS &&
		       at != DIRECTORY_STREAM && at != FILESYSTEM_STAT &&
		       at != MISSING_ROOT && at != ROOT_STAT &&
		       at != STACK_ALLOC;
	alarm(15);
	assert(mkdtemp(root));
	assert(snprintf(file, sizeof(file), "%s/child", root) > 0);
	assert(snprintf(fc, sizeof(fc), "%s.fc", root) > 0);
	assert(snprintf(missing, sizeof(missing), "%s/missing", root) > 0);
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
	fault = at;
	inject = true;
	clobber = overwrite;
	int rc = selinux_restorecon_parallel(
		at == MISSING_ROOT ? missing : root, flags, threads);
	int saved_errno = errno;
	assert(rc == (counted ? 0 : -1));
	assert(at == MISSING_ROOT || hits > 0);
	if (!counted)
		assert(saved_errno == errors[at]);
	/* Neither the failure nor a worker's ambient errno may poison reuse. */
	inject = false;
	assert(selinux_restorecon_parallel(root, flags, threads) == 0);
	if (at == LABEL_WRITE || at == LABEL_READ) {
		inject = true;
		assert(selinux_restorecon(
			       file, flags & ~SELINUX_RESTORECON_RECURSE) ==
		       -1);
		assert(errno == errors[at]);
	}
	clobber = inject = false;
	assert(unlink(file) == 0 && rmdir(root) == 0 && unlink(fc) == 0);
	selinux_restorecon_set_sehandle(NULL);
}

int main(int argc, char **argv)
{
	const size_t threads[] = { 1, 2, 8 };
	const unsigned int options[] = { 0, SELINUX_RESTORECON_ABORT_ON_ERROR,
					 SELINUX_RESTORECON_COUNT_ERRORS };
	unsigned int cases = 0;
	for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); i++) {
		for (int at = 0; at < FAULT_COUNT; at++) {
			if (argc > 1 && at != atoi(argv[1]))
				continue;
			for (size_t j = 0;
			     j < sizeof(options) / sizeof(options[0]); j++) {
				for (int overwrite = 0; overwrite < 2;
				     overwrite++) {
					pid_t pid = fork();
					int status;
					assert(pid >= 0);
					if (!pid) {
						run_case(threads[i], at,
							 options[j], overwrite);
						_exit(0);
					}
					assert(waitpid(pid, &status, 0) == pid);
					assert(WIFEXITED(status) &&
					       WEXITSTATUS(status) == 0);
					cases++;
				}
			}
		}
	}
	printf("Restorecon errno: %u cases passed.\n", cases);
	return 0;
}
