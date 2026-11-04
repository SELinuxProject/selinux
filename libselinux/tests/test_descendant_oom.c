#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <selinux/label.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *live[128];
static unsigned calls, outstanding, fail_at, cases;
static bool active;
static uint8_t cached[20];

void *__real_malloc(size_t size);
void __real_free(void *ptr);

void *__wrap_malloc(size_t size);
void __wrap_free(void *ptr);
ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size);

void *__wrap_malloc(size_t size)
{
	if (active && ++calls == fail_at) {
		errno = ENOMEM;
		return NULL;
	}
	void *ptr = __real_malloc(size);
	if (active && ptr) {
		unsigned i;
		for (i = 0; i < 128 && live[i]; i++) {
		}
		assert(i < 128);
		live[i] = ptr;
		outstanding++;
	}
	return ptr;
}

void __wrap_free(void *ptr)
{
	for (unsigned i = 0; ptr && i < 128; i++) {
		if (live[i] == ptr) {
			live[i] = NULL;
			outstanding--;
			break;
		}
	}
	__real_free(ptr);
}

ssize_t __wrap_getxattr(const char *path, const char *name, void *value,
			size_t size)
{
	(void)path;
	assert(!strcmp(name, "security.sehash") && size >= sizeof(cached));
	memcpy(value, cached, sizeof(cached));
	return sizeof(cached);
}

static struct selabel_handle *open_rules(const char *file, const char *rules,
					 unsigned jit)
{
	FILE *fp = fopen(file, "we");
	assert(fp);
	assert(fputs(rules, fp) >= 0 && fclose(fp) == 0);
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, file },
		{ SELABEL_OPT_BASEONLY, "1" },
		{ SELABEL_OPT_DIGEST, "1" },
		{ SELABEL_OPT_JIT, jit ? "1" : NULL },
	};
	struct selabel_handle *h = selabel_open(SELABEL_CTX_FILE, opts, 4);
	assert(h);
	return h;
}

static void check(struct selabel_handle *h, const char *path, unsigned first)
{
	uint8_t healthy[20], digest[20], sentinel[20];
	memset(sentinel, 0xa5, sizeof(sentinel));
	/* Warm regex caches before tracking result-list ownership. */
	assert(selabel_hash_all_partial_matches(h, path, healthy));
	calls = fail_at = 0;
	active = true;
	assert(selabel_hash_all_partial_matches(h, path, digest));
	active = false;
	assert(!outstanding && !memcmp(digest, healthy, sizeof(digest)));
	unsigned allocations = calls;
	assert(allocations >= first);
	for (unsigned n = first; n <= allocations; n++) {
		for (unsigned ambient = 0; ambient < 2; ambient++) {
			memcpy(digest, sentinel, sizeof(digest));
			calls = 0;
			fail_at = n;
			errno = ambient ? ENOENT : EIO;
			active = true;
			bool rc = selabel_hash_all_partial_matches(h, path,
								   digest);
			active = false;
			assert(!rc && errno == ENOMEM && calls == n);
			assert(!outstanding &&
			       !memcmp(digest, sentinel, sizeof(digest)));
			/* Even a cached healthy digest cannot turn failure into a hit. */
			memcpy(cached, healthy, sizeof(cached));
			uint8_t *calculated = NULL, *stored = NULL;
			size_t length = 0;
			calls = 0;
			active = true;
			rc = selabel_get_digests_all_partial_matches(
				h, path, &calculated, &stored, &length);
			active = false;
			assert(!rc && errno == ENOMEM && !calculated && stored);
			assert(length == sizeof(cached) && !outstanding);
			free(stored);
			fail_at = 0;
			calls = 0;
			active = true;
			assert(selabel_hash_all_partial_matches(h, path,
								digest));
			active = false;
			assert(!outstanding &&
			       !memcmp(digest, healthy, sizeof(digest)));
			cases++;
		}
	}
}

int main(void)
{
	const char *rules[] = {
		"/audit/branch/leaf system_u:object_r:one_t:s0\n"
		"/audit/broom/leaf system_u:object_r:two_t:s0\n",
		"/audit/branch/deep/leaf system_u:object_r:one_t:s0\n"
		"/audit/branch/deep/other system_u:object_r:two_t:s0\n"
		"/audit/broom/leaf system_u:object_r:three_t:s0\n",
		"/audit/branch/deep/leaf.* system_u:object_r:one_t:s0\n"
		"/audit/branch/deep/other.* system_u:object_r:two_t:s0\n"
		"/audit/broom/leaf system_u:object_r:three_t:s0\n",
		"/audit/.* system_u:object_r:base_t:s0\n"
		"/audit/branch/deep/leaf system_u:object_r:one_t:s0\n"
		"/audit/broom/leaf system_u:object_r:two_t:s0\n",
		"/audit/blank/deep/leaf <<none>>\n"
		"/audit/branch/deep/leaf system_u:object_r:one_t:s0\n"
		"/audit/broom/leaf <<none>>\n",
	};
	char file[] = "/tmp/selinux-descendant-oom-XXXXXX";
	int fd = mkstemp(file);
	assert(fd >= 0 && close(fd) == 0);
	for (unsigned jit = 0; jit < 2; jit++) {
		for (unsigned i = 0; i < sizeof(rules) / sizeof(rules[0]);
		     i++) {
			struct selabel_handle *h =
				open_rules(file, rules[i], jit);
			/* The base regex's allocation belongs to the separate matcher path. */
			check(h, "/audit/b", i == 3 ? 2 : 1);
			check(h, "/audit/branch", i == 3 ? 2 : 1);
			selabel_close(h);
		}
		struct selabel_handle *h = open_rules(
			file, "/audit/blank/deep/leaf <<none>>\n", jit);
		uint8_t digest[20];
		errno = ENOMEM;
		assert(!selabel_hash_all_partial_matches(h, "/audit/b",
							 digest));
		assert(errno == ENOENT);
		errno = ENOMEM;
		assert(!selabel_partial_match(h, "/audit/b"));
		assert(errno == ENOENT);
		selabel_close(h);
		cases++;
	}
	assert(unlink(file) == 0);
	printf("descendant-oom: %u scenarios passed\n", cases);
	return 0;
}
