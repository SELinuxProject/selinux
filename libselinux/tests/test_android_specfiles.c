#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "label_internal.h"

static char path[256];
static unsigned fail, hits, closes, cases;
static int tracking;
static void *list, *name;

void *__wrap_calloc(size_t n, size_t size);
char *__wrap_strdup(const char *s);
void __wrap_free(void *p);
int __wrap_fclose(FILE *fp);

void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size)
{
	if (tracking && n == 1 && size == sizeof(char *)) {
		if (fail == 1) {
			hits++;
			errno = ENOMEM;
			return NULL;
		}
		assert(!list);
		list = __real_calloc(n, size);
		return list;
	}
	return __real_calloc(n, size);
}

char *__real_strdup(const char *);
char *__wrap_strdup(const char *s)
{
	if (tracking && !strcmp(s, path)) {
		if (fail == 2) {
			hits++;
			errno = ENOMEM;
			return NULL;
		}
		/* Digest bookkeeping also duplicates the path. Track the first. */
		char *p = __real_strdup(s);
		if (!name)
			name = p;
		return p;
	}
	return __real_strdup(s);
}

void __real_free(void *);
void __wrap_free(void *p)
{
	if (p == list)
		list = NULL;
	if (p == name)
		name = NULL;
	__real_free(p);
}

int __real_fclose(FILE *);
int __wrap_fclose(FILE *fp)
{
	if (tracking)
		closes++;
	return __real_fclose(fp);
}

static int validate(char **context)
{
	assert(context && *context);
	return 0;
}

static void put(const char *text)
{
	FILE *fp = fopen(path, "we");
	assert(fp);
	assert(fputs(text, fp) >= 0 && fclose(fp) == 0);
}

static struct selabel_handle *open_handle(unsigned backend, unsigned digest,
					  unsigned validating)
{
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, path },
		{ SELABEL_OPT_DIGEST, digest ? "1" : NULL },
		{ SELABEL_OPT_VALIDATE, validating ? "1" : NULL },
	};
	assert(!list && !name);
	closes = hits = 0;
	tracking = 1;
	struct selabel_handle *h = selabel_open(backend, opts, 3);
	tracking = 0;
	assert(closes == 1);
	return h;
}

static void check_handle(struct selabel_handle *h)
{
	assert(h && list && name);
	assert(h->spec_files == list && h->spec_files_len == 1);
	assert(h->spec_files[0] == name && !strcmp(h->spec_files[0], path));
}

static void close_handle(struct selabel_handle *h)
{
	selabel_close(h);
	assert(!list && !name);
}

int main(void)
{
	char dir[] = "/tmp/selinux-android-specfiles-XXXXXX";
	assert(mkdtemp(dir));
	snprintf(path, sizeof(path), "%s/contexts", dir);
	union selinux_callback cb = { .func_validate = validate };
	selinux_set_callback(SELINUX_CB_VALIDATE, cb);
	for (unsigned backend = SELABEL_CTX_ANDROID_PROP;
	     backend <= SELABEL_CTX_ANDROID_SERVICE; backend++) {
		for (unsigned digest = 0; digest < 2; digest++) {
			for (unsigned validating = 0; validating < 2;
			     validating++) {
				for (unsigned match = 0; match < 3; match++) {
					put(match == 1 ?
						    "* system_u:object_r:test_t:s0\n" :
						    "test.key system_u:object_r:test_t:s0\n");
					struct selabel_handle *h = open_handle(
						backend, digest, validating);
					check_handle(h);
					for (unsigned raw = 0; raw < 2; raw++) {
						char *context = NULL;
						const char *key =
							match == 0 ?
								"test.key" :
								"missing";
						int rc =
							raw ? selabel_lookup_raw(
								      h,
								      &context,
								      key, 0) :
							      selabel_lookup(
								      h,
								      &context,
								      key, 0);
						if (match == 2)
							assert(rc == -1 &&
							       errno ==
								       ENOENT &&
							       !context);
						else
							assert(rc == 0 &&
							       !strcmp(context,
								       "system_u:object_r:test_t:s0"));
						freecon(context);
						cases++;
					}
					if (digest) {
						unsigned char *hash;
						char **files;
						size_t length, count;
						assert(selabel_digest(
							       h, &hash,
							       &length, &files,
							       &count) == 0);
						assert(hash && length == 20 &&
						       count == 1 &&
						       !strcmp(files[0], path));
					}
					close_handle(h);
				}
				for (fail = 1; fail <= 2; fail++) {
					struct selabel_handle *h = open_handle(
						backend, digest, validating);
					assert(!h && errno == ENOMEM &&
					       hits == 1 && !list && !name);
					cases++;
				}
				fail = 0;
				struct selabel_handle *h = open_handle(
					backend, digest, validating);
				check_handle(h);
				close_handle(h);
				cases++;
			}
		}
		put("");
		struct selabel_handle *h = open_handle(backend, 0, 0);
		check_handle(h);
		close_handle(h);
		cases++;
		put("invalid-line\n");
		h = open_handle(backend, 0, 0);
		assert(!h && !list && !name);
		cases++;
	}
	assert(unlink(path) == 0 && rmdir(dir) == 0);
	printf("android-specfiles: %u cases passed\n", cases);
	return 0;
}
