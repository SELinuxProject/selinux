#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pcre2.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static unsigned limits, writes, cases;
static int injected;
static char recorded[128];
static char root[] = "/tmp/selinux-match-limit-XXXXXX";
static char fc[256];
static unsigned char cached[20];
static long filesystem;
static unsigned digest_writes;

int __wrap_fstatfs(int fd, struct statfs *buf);
int __wrap_fstatfs64(int fd, struct statfs64 *buf);
int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags);
ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size);
int __wrap_pcre2_match_8(const pcre2_code *code, PCRE2_SPTR subject,
			 PCRE2_SIZE length, PCRE2_SIZE start, uint32_t options,
			 pcre2_match_data *data, pcre2_match_context *context);
int __wrap_getfilecon_raw(const char *path, char **context);
int __wrap_setfilecon_raw(const char *path, const char *context);

int __real_fstatfs(int fd, struct statfs *buf);
int __wrap_fstatfs(int fd, struct statfs *buf)
{
	int rc = __real_fstatfs(fd, buf);
	if (!rc && filesystem)
		buf->f_type = filesystem;
	return rc;
}

int __real_fstatfs64(int fd, struct statfs64 *buf);
int __wrap_fstatfs64(int fd, struct statfs64 *buf)
{
	int rc = __real_fstatfs64(fd, buf);
	if (!rc && filesystem)
		buf->f_type = filesystem;
	return rc;
}

int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags)
{
	(void)fd;
	(void)name;
	(void)value;
	(void)size;
	(void)flags;
	__atomic_add_fetch(&digest_writes, 1, __ATOMIC_RELAXED);
	return 0;
}

ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size)
{
	(void)path;
	assert(!strcmp(name, "security.sehash") && size >= sizeof(cached));
	memcpy(value, cached, sizeof(cached));
	return sizeof(cached);
}

int __real_pcre2_match_8(const pcre2_code *, PCRE2_SPTR, PCRE2_SIZE, PCRE2_SIZE,
			 uint32_t, pcre2_match_data *, pcre2_match_context *);
int __wrap_pcre2_match_8(const pcre2_code *code, PCRE2_SPTR subject,
			 PCRE2_SIZE length, PCRE2_SIZE start, uint32_t options,
			 pcre2_match_data *data, pcre2_match_context *context)
{
	int rc = injected ? injected :
			    __real_pcre2_match_8(code, subject, length, start,
						 options, data, context);
	if (rc == PCRE2_ERROR_MATCHLIMIT)
		__atomic_add_fetch(&limits, 1, __ATOMIC_RELAXED);
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
	assert(stat(path, &st) == 0);
	assert(strlen(context) < sizeof(recorded));
	strcpy(recorded, context);
	writes++;
	return 0;
}

static struct selabel_handle *open_rules(const char *rules, unsigned jit)
{
	FILE *fp = fopen(fc, "we");
	assert(fp);
	assert(fputs(rules, fp) >= 0 && fclose(fp) == 0);
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, fc },
		{ SELABEL_OPT_BASEONLY, "1" },
		{ SELABEL_OPT_JIT, jit ? "1" : NULL },
		{ SELABEL_OPT_DIGEST, "1" },
	};
	struct selabel_handle *h = selabel_open(SELABEL_CTX_FILE, opts, 4);
	assert(h);
	return h;
}

static void real_limits(unsigned jit)
{
	for (unsigned complex = 0; complex < 2; complex++) {
		for (unsigned none = 0; none < 2; none++) {
			char rules[512];
			snprintf(rules, sizeof(rules),
				 "/audit/.* system_u:object_r:fallback_t:s0\n"
				 "/audit/(%s+b|a+) %s\n",
				 complex ? "(a|aa)" : "a",
				 none ? "<<none>>" :
					"system_u:object_r:required_t:s0");
			struct selabel_handle *h = open_rules(rules, jit);
			selinux_restorecon_set_sehandle(h);
			for (unsigned len = 20; len <= 34; len += 14) {
				char key[128] = "/audit/", path[256],
				     *context = NULL;
				memset(key + 7, 'a', len);
				key[7 + len] = '\0';
				limits = 0;
				errno = 0;
				int rc = selabel_lookup_raw(h, &context, key,
							    S_IFREG);
				if (complex && len == 34) {
					assert(rc == -1 && errno == EIO &&
					       limits == 1 && !context);
				} else if (none) {
					assert(rc == -1 && errno == ENOENT &&
					       !context && !limits);
				} else {
					assert(rc == 0 &&
					       strstr(context,
						      ":required_t:") &&
					       !limits);
				}
				freecon(context);
				snprintf(path, sizeof(path), "%s%s", root, key);
				int fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
					      0600);
				assert(fd >= 0 && close(fd) == 0);
				writes = 0;
				rc = selinux_restorecon(
					path,
					SELINUX_RESTORECON_IGNORE_MOUNTS |
						SELINUX_RESTORECON_SKIP_DIGEST |
						SELINUX_RESTORECON_SET_SPECFILE_CTX);
				if (complex && len == 34)
					assert(rc == -1 && !writes);
				else {
					assert(rc == 0 && writes == !none);
					if (!none)
						assert(strstr(recorded,
							      ":required_t:"));
				}
				assert(unlink(path) == 0);
				cases++;
			}
			selinux_restorecon_set_sehandle(NULL);
		}
	}
}

static void hashes(unsigned jit)
{
	char key[128] = "/audit/", rules[512];
	unsigned char hash[20], sentinel[20];
	memset(key + 7, 'a', 34);
	key[41] = '\0';
	memset(sentinel, 0xa5, sizeof(sentinel));
	for (unsigned version = 0; version < 2; version++) {
		snprintf(
			rules, sizeof(rules),
			"/audit/.* system_u:object_r:fallback_t:s0\n"
			"/audit/((a|aa)+b|a+)/child system_u:object_r:%s_t:s0\n",
			version ? "new" : "old");
		struct selabel_handle *h = open_rules(rules, jit);
		memcpy(hash, sentinel, sizeof(hash));
		limits = 0;
		errno = 0;
		assert(!selabel_hash_all_partial_matches(h, key, hash));
		assert(errno == EIO && limits == 1 &&
		       !memcmp(hash, sentinel, sizeof(hash)));
		assert(selabel_partial_match(h, key));
		assert(selabel_hash_all_partial_matches(h, "/audit/a", hash));
		selabel_close(h);
		cases++;
	}
	/* A previously cached digest cannot make a failed calculation a hit. */
	struct selabel_handle *h =
		open_rules("/audit/.* system_u:object_r:base_t:s0\n", jit);
	assert(selabel_hash_all_partial_matches(h, key, cached));
	unsigned char *calculated = NULL, *stored = NULL;
	size_t length;
	assert(selabel_get_digests_all_partial_matches(h, key, &calculated,
						       &stored, &length));
	free(calculated);
	free(stored);
	injected = PCRE2_ERROR_MATCHLIMIT;
	assert(!selabel_get_digests_all_partial_matches(h, key, &calculated,
							&stored, &length));
	assert(!calculated && stored && length == sizeof(cached));
	free(stored);
	injected = 0;
	selabel_close(h);
	cases++;
}

static void error_paths(unsigned jit)
{
	const int errors[] = { PCRE2_ERROR_MATCHLIMIT, PCRE2_ERROR_DEPTHLIMIT,
			       PCRE2_ERROR_NOMEMORY };
	struct selabel_handle *h =
		open_rules("/audit/.* system_u:object_r:base_t:s0\n"
			   "/audit/branch/child system_u:object_r:child_t:s0\n"
			   "/alias system_u:object_r:alias_t:s0\n",
			   jit);
	for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		unsigned char digest[20];
		char *context = NULL;
		const char *aliases[] = { "/alias", NULL };
		injected = errors[i];
		errno = ENOENT;
		assert(selabel_lookup_raw(h, &context, "/audit/x", S_IFREG) ==
		       -1);
		assert(errno == EIO && !context);
		assert(selabel_partial_match(h, "/audit/x"));
		assert(errno == EIO);
		/* Descendant literals must not resurrect an incomplete hash. */
		assert(!selabel_hash_all_partial_matches(h, "/audit/branch",
							 digest));
		assert(errno == EIO);
		assert(selabel_lookup_best_match_raw(h, &context, "/audit/x",
						     aliases, S_IFREG) == -1);
		assert(errno == EIO && !context);
		const char *bad_aliases[] = { "/audit/x", "/alias", NULL };
		assert(selabel_lookup_best_match_raw(h, &context, "/missing",
						     bad_aliases,
						     S_IFREG) == -1);
		assert(errno == EIO && !context);
		injected = 0;
		errno = EIO;
		assert(!selabel_partial_match(h, "/missing"));
		assert(errno == ENOENT);
		assert(selabel_lookup_raw(h, &context, "/audit/x", S_IFREG) ==
		       0);
		freecon(context);
		cases++;
	}
	selabel_close(h);
}

static void recursive(void)
{
	char dir[256], child[256], rules[768];
	const size_t threads[] = { 1, 2, 8 };
	snprintf(dir, sizeof(dir), "%s/recursive", root);
	snprintf(child, sizeof(child), "%s/recursive/child", root);
	assert(mkdir(dir, 0700) == 0);
	int fd = open(child, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	snprintf(rules, sizeof(rules),
		 "/.* system_u:object_r:base_t:s0\n"
		 "%s system_u:object_r:child_t:s0\n",
		 child);
	assert(selinux_restorecon_set_alt_rootpath("/") == 0);
	for (unsigned sysfs = 0; sysfs < 2; sysfs++) {
		filesystem = sysfs ? 0x62656572 : 0xef53;
		for (unsigned i = 0; i < sizeof(threads) / sizeof(threads[0]);
		     i++) {
			struct selabel_handle *h = open_rules(rules, 0);
			selinux_restorecon_set_sehandle(h);
			injected = PCRE2_ERROR_MATCHLIMIT;
			writes = digest_writes = 0;
			int rc = selinux_restorecon_parallel(
				dir,
				SELINUX_RESTORECON_RECURSE |
					SELINUX_RESTORECON_IGNORE_MOUNTS |
					SELINUX_RESTORECON_SET_SPECFILE_CTX,
				threads[i]);
			assert(rc == -1 && writes == 1 && !digest_writes);
			assert(strstr(recorded, ":child_t:"));
			injected = 0;
			selinux_restorecon_set_sehandle(NULL);
			cases++;
		}
	}
	filesystem = 0;
	assert(unlink(child) == 0 && rmdir(dir) == 0);
}

int main(void)
{
	char path[256];
	assert(mkdtemp(root));
	snprintf(fc, sizeof(fc), "%s/contexts", root);
	snprintf(path, sizeof(path), "%s/audit", root);
	assert(mkdir(path, 0700) == 0);
	assert(selinux_restorecon_set_alt_rootpath(root) == 0);
	for (unsigned jit = 0; jit < 2; jit++) {
		real_limits(jit);
		hashes(jit);
		error_paths(jit);
	}
	recursive();
	assert(unlink(fc) == 0 && rmdir(path) == 0 && rmdir(root) == 0);
	printf("match-limit: %u scenarios passed\n", cases);
	return 0;
}
