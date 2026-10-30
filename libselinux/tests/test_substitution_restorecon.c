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

static struct entry {
	ino_t ino;
	unsigned char hash[20];
} entries[16];
static unsigned nentries, attempts;
static ino_t target;
static char last_context[128];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int __real_fstatfs(int fd, struct statfs *buf);
int __wrap_fstatfs(int fd, struct statfs *buf)
{
	int rc = __real_fstatfs(fd, buf);
	if (!rc)
		buf->f_type = 0xef53;
	return rc;
}
int __real_fstatfs64(int fd, struct statfs64 *buf);
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
	struct stat sb;
	assert(stat(path, &sb) == 0);
	assert(pthread_mutex_lock(&lock) == 0);
	if (sb.st_ino == target) {
		attempts++;
		assert(strlen(context) < sizeof(last_context));
		strcpy(last_context, context);
	}
	assert(pthread_mutex_unlock(&lock) == 0);
	return 0;
}
ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size)
{
	struct stat sb;
	assert(!strcmp(name, "security.sehash") && size >= 20);
	assert(stat(path, &sb) == 0);
	assert(pthread_mutex_lock(&lock) == 0);
	for (unsigned i = 0; i < nentries; i++) {
		if (entries[i].ino == sb.st_ino) {
			memcpy(value, entries[i].hash, 20);
			assert(pthread_mutex_unlock(&lock) == 0);
			return 20;
		}
	}
	assert(pthread_mutex_unlock(&lock) == 0);
	errno = ENODATA;
	return -1;
}
int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags)
{
	struct stat sb;
	(void)flags;
	assert(!strcmp(name, "security.sehash") && size == 20);
	assert(fstat(fd, &sb) == 0);
	assert(pthread_mutex_lock(&lock) == 0);
	unsigned i;
	for (i = 0; i < nentries && entries[i].ino != sb.st_ino; i++) {
	}
	if (i == nentries) {
		assert(nentries < 16);
		entries[nentries++].ino = sb.st_ino;
	}
	memcpy(entries[i].hash, value, 20);
	assert(pthread_mutex_unlock(&lock) == 0);
	return 0;
}

static void run(unsigned wildcard, size_t threads)
{
	char tmp[] = "/tmp/doex-wild-restore-XXXXXX", root[512], path[512],
	     fc[512], subs[512];
	struct stat sb;
	assert(mkdtemp(tmp));
	snprintf(root, sizeof(root), "%s/demo", tmp);
	assert(mkdir(root, 0700) == 0);
	snprintf(path, sizeof(path), "%s/demo/usr", tmp);
	assert(mkdir(path, 0700) == 0);
	snprintf(path, sizeof(path), "%s/demo/usr/bin", tmp);
	assert(mkdir(path, 0700) == 0);
	snprintf(path, sizeof(path), "%s/demo/usr/bin/tool", tmp);
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	assert(stat(path, &sb) == 0);
	target = sb.st_ino;
	snprintf(fc, sizeof(fc), "%s/file_contexts", tmp);
	snprintf(subs, sizeof(subs), "%s/file_contexts.subs_dist", tmp);
	FILE *fp = fopen(subs, "we");
	assert(fp);
	fprintf(fp, "%s/%s /\n", tmp, wildcard ? "*" : "demo");
	assert(fclose(fp) == 0);
	unsigned flags = SELINUX_RESTORECON_RECURSE |
			 SELINUX_RESTORECON_IGNORE_MOUNTS |
			 SELINUX_RESTORECON_SET_SPECFILE_CTX;
	for (unsigned version = 0; version <= 1; version++) {
		fp = fopen(fc, "we");
		assert(fp);
		fprintf(fp, "%s(/.*)? system_u:object_r:staging_t:s0\n", tmp);
		fprintf(fp, "/usr/bin/tool system_u:object_r:%s_t:s0\n",
			version ? "new" : "old");
		assert(fclose(fp) == 0);
		struct selinux_opt opts[] = { { SELABEL_OPT_PATH, fc },
					      { SELABEL_OPT_DIGEST, "1" } };
		struct selabel_handle *h =
			selabel_open(SELABEL_CTX_FILE, opts, 2);
		assert(h);
		selinux_restorecon_set_sehandle(h);
		unsigned before = attempts;
		assert(selinux_restorecon_parallel(root, flags, threads) == 0);
		printf("wildcard=%u threads=%zu version=%u target-writes=%u stored-dirs=%u last-label=%s\n",
		       wildcard, threads, version, attempts - before, nentries,
		       last_context);
		assert(attempts - before == 1);
		assert(strstr(last_context, version ? ":new_t:" : ":old_t:"));
		before = attempts;
		assert(selinux_restorecon_parallel(root, flags, threads) == 0);
		assert(attempts == before);
		if (version) {
			before = attempts;
			assert(selinux_restorecon_parallel(
				       root,
				       flags | SELINUX_RESTORECON_SKIP_DIGEST,
				       threads) == 0);
			printf("wildcard=%u threads=%zu skip-digest target-writes=%u last-label=%s\n",
			       wildcard, threads, attempts - before,
			       last_context);
			assert(attempts - before == 1 &&
			       strstr(last_context, ":new_t:"));
		}
		selinux_restorecon_set_sehandle(NULL);
	}
	assert(unlink(path) == 0);
	snprintf(path, sizeof(path), "%s/demo/usr/bin", tmp);
	assert(rmdir(path) == 0);
	snprintf(path, sizeof(path), "%s/demo/usr", tmp);
	assert(rmdir(path) == 0);
	assert(rmdir(root) == 0);
	assert(unlink(fc) == 0 && unlink(subs) == 0);
	assert(rmdir(tmp) == 0);
}

int main(void)
{
	const size_t threads[] = { 1, 2, 8 };
	for (unsigned w = 0; w <= 1; w++) {
		for (unsigned t = 0; t < 3; t++) {
			fflush(NULL);
			pid_t pid = fork();
			assert(pid >= 0);
			if (!pid) {
				alarm(20);
				run(w, threads[t]);
				fflush(stdout);
				_exit(0);
			}
			int status;
			assert(waitpid(pid, &status, 0) == pid);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		}
	}
	return 0;
}
