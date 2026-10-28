/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t release = PTHREAD_COND_INITIALIZER;
static bool block_relabel, fail_relabel, ready;
static unsigned int pending, attempts, barriers, writes;
static unsigned char digest[20];
static bool stored;
static bool nested;

int __wrap_getfilecon_raw(const char *path, char **context);
int __wrap_setfilecon_raw(const char *path, const char *context);
ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size);
int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags);
int __real_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int __real_fstatfs(int fd, struct statfs *buf);
int __wrap_fstatfs(int fd, struct statfs *buf);
int __real_fstatfs64(int fd, struct statfs64 *buf);
int __wrap_fstatfs64(int fd, struct statfs64 *buf);

/* Keep digest coverage even when the temporary directory is on tmpfs. */
int __wrap_fstatfs(int fd, struct statfs *buf)
{
	int rc = __real_fstatfs(fd, buf);
	if (!rc)
		buf->f_type = 0xef53;
	return rc;
}

int __wrap_fstatfs64(int fd, struct statfs64 *buf)
{
	int rc = __real_fstatfs64(fd, buf);
	if (!rc)
		buf->f_type = 0xef53;
	return rc;
}

int __wrap_getfilecon_raw(const char *path, char **context)
{
	(void)path;
	*context = NULL;
	errno = ENODATA;
	return -1;
}

int __wrap_setfilecon_raw(const char *path, const char *context)
{
	struct stat st;
	(void)context;
	assert(stat(path, &st) == 0);
	if (!S_ISREG(st.st_mode))
		return 0;
	assert(pthread_mutex_lock(&lock) == 0);
	attempts++;
	pending++;
	while (block_relabel && !ready)
		assert(__real_pthread_cond_wait(&release, &lock) == 0);
	pending--;
	assert(pthread_mutex_unlock(&lock) == 0);
	if (fail_relabel) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

/* Release the blocked label write only once traversal reaches its barrier. */
int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	assert(cond != &release);
	assert(pthread_mutex_lock(&lock) == 0);
	barriers++;
	ready = true;
	assert(pthread_cond_broadcast(&release) == 0);
	assert(pthread_mutex_unlock(&lock) == 0);
	return __real_pthread_cond_wait(cond, mutex);
}

ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size)
{
	(void)path;
	assert(!strcmp(name, "security.sehash"));
	if (!stored || nested) {
		errno = ENODATA;
		return -1;
	}
	assert(size >= sizeof(digest));
	memcpy(value, digest, sizeof(digest));
	return sizeof(digest);
}

int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags)
{
	(void)fd;
	(void)flags;
	assert(!strcmp(name, "security.sehash"));
	assert(size == sizeof(digest));
	assert(pthread_mutex_lock(&lock) == 0);
	assert(!pending && !fail_relabel);
	if (block_relabel)
		assert(barriers && attempts);
	memcpy(digest, value, size);
	stored = true;
	writes++;
	assert(pthread_mutex_unlock(&lock) == 0);
	return 0;
}

static void run_case(size_t threads, unsigned int extra, bool failure,
		     bool deep)
{
	char root[] = "/tmp/restorecon-digest-XXXXXX";
	char file[1024], fc[256], directory[1024];
	FILE *fp;
	int fd, rc;
	unsigned int flags = SELINUX_RESTORECON_RECURSE |
			     SELINUX_RESTORECON_IGNORE_MOUNTS |
			     SELINUX_RESTORECON_SET_SPECFILE_CTX | extra;
	bool cache = !(extra & (SELINUX_RESTORECON_SKIP_DIGEST |
				SELINUX_RESTORECON_NOCHANGE));
	struct selabel_handle *handle;

	alarm(15);
	nested = deep;
	assert(mkdtemp(root));
	strcpy(directory, root);
	if (deep) {
		for (unsigned int i = 0; i < 20; i++) {
			strcat(directory, "/sub");
			assert(mkdir(directory, 0700) == 0);
		}
	}
	assert(snprintf(file, sizeof(file), "%s/child", directory) > 0);
	assert(snprintf(fc, sizeof(fc), "%s.fc", root) > 0);
	fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	fp = fopen(fc, "w");
	assert(fp);
	assert(fprintf(fp, "%s(/.*)? system_u:object_r:test_t:s0\n", root) > 0);
	assert(fclose(fp) == 0);
	struct selinux_opt options[] = { { SELABEL_OPT_PATH, fc },
					 { SELABEL_OPT_DIGEST, (char *)1 } };
	handle = selabel_open(SELABEL_CTX_FILE, options, 2);
	assert(handle);
	selinux_restorecon_set_sehandle(handle);
	block_relabel = threads > 1 && cache;
	fail_relabel = failure;
	rc = selinux_restorecon_parallel(root, flags, threads);
	assert(rc == (failure && !(extra & SELINUX_RESTORECON_COUNT_ERRORS) ?
			      -1 :
			      0));
	assert(!pending);
	assert(stored == (cache && !failure));
	assert(writes == (cache && !failure ? (deep ? 21U : 1U) : 0U));
	if (block_relabel)
		assert(barriers > 0);

	unsigned int before = attempts;
	block_relabel = fail_relabel = false;
	rc = selinux_restorecon(root, flags);
	assert(rc == 0);
	if (extra & SELINUX_RESTORECON_NOCHANGE)
		assert(attempts == 0 && writes == 0);
	else
		assert(attempts == before + !(cache && !failure && !deep));
	assert(unlink(file) == 0);
	if (deep) {
		for (unsigned int i = 0; i < 20; i++) {
			assert(rmdir(directory) == 0);
			*strrchr(directory, '/') = '\0';
		}
	}
	assert(rmdir(root) == 0);
	assert(unlink(fc) == 0);
	selinux_restorecon_set_sehandle(NULL);
}

int main(void)
{
	const unsigned int options[] = { 0, SELINUX_RESTORECON_ABORT_ON_ERROR,
					 SELINUX_RESTORECON_COUNT_ERRORS,
					 SELINUX_RESTORECON_SKIP_DIGEST,
					 SELINUX_RESTORECON_NOCHANGE };
	const size_t threads[] = { 1, 2, 8 };
	unsigned int cases = 0;
	for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); i++) {
		for (size_t j = 0; j < sizeof(options) / sizeof(options[0]);
		     j++) {
			for (unsigned int fail = 0; fail < 2; fail++) {
				if (fail &&
				    options[j] == SELINUX_RESTORECON_NOCHANGE)
					continue;
				for (unsigned int deep = 0; deep < 2; deep++) {
					pid_t pid = fork();
					int status;
					assert(pid >= 0);
					if (!pid) {
						run_case(threads[i], options[j],
							 fail, deep);
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
	printf("Restorecon digest completion: %u cases passed.\n", cases);
	return 0;
}
