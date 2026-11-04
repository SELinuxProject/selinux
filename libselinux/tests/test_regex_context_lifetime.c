#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pcre2.h>
#include <pthread.h>
#include <selinux/label.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *live[32];
static unsigned kinds[32], allocated[2], freed[2], failures[2];
static unsigned fail_compile, fail_match, jit;
static void *library;
static const char *file;

static void track(void *ptr, unsigned kind)
{
	unsigned i;
	assert(ptr);
	for (i = 0; i < 32 && live[i]; i++) {
	}
	assert(i < 32);
	live[i] = ptr;
	kinds[i] = kind;
	allocated[kind]++;
}

static void untrack(void *ptr, unsigned kind)
{
	if (!ptr)
		return;
	unsigned i;
	for (i = 0; i < 32 && live[i] != ptr; i++) {
	}
	assert(i < 32 && kinds[i] == kind);
	live[i] = NULL;
	freed[kind]++;
}

pcre2_compile_context *
pcre2_compile_context_create_8(pcre2_general_context *ctx);
pcre2_match_context *pcre2_match_context_create_8(pcre2_general_context *ctx);
void pcre2_compile_context_free_8(pcre2_compile_context *ptr);
void pcre2_match_context_free_8(pcre2_match_context *ptr);

pcre2_compile_context *
pcre2_compile_context_create_8(pcre2_general_context *ctx)
{
	if (fail_compile) {
		fail_compile--;
		failures[0]++;
		errno = ENOMEM;
		return NULL;
	}
	pcre2_compile_context *(*fn)(pcre2_general_context *) =
		dlsym(RTLD_NEXT, "pcre2_compile_context_create_8");
	assert(fn);
	pcre2_compile_context *ptr = fn(ctx);
	track(ptr, 0);
	return ptr;
}

pcre2_match_context *pcre2_match_context_create_8(pcre2_general_context *ctx)
{
	if (fail_match) {
		fail_match--;
		failures[1]++;
		errno = ENOMEM;
		return NULL;
	}
	pcre2_match_context *(*fn)(pcre2_general_context *) =
		dlsym(RTLD_NEXT, "pcre2_match_context_create_8");
	assert(fn);
	pcre2_match_context *ptr = fn(ctx);
	track(ptr, 1);
	return ptr;
}

void pcre2_compile_context_free_8(pcre2_compile_context *ptr)
{
	void (*fn)(pcre2_compile_context *) =
		dlsym(RTLD_NEXT, "pcre2_compile_context_free_8");
	assert(fn);
	untrack(ptr, 0);
	fn(ptr);
}

void pcre2_match_context_free_8(pcre2_match_context *ptr)
{
	void (*fn)(pcre2_match_context *) =
		dlsym(RTLD_NEXT, "pcre2_match_context_free_8");
	assert(fn);
	untrack(ptr, 1);
	fn(ptr);
}

static void *worker(void *unused)
{
	(void)unused;
	struct selabel_handle *(*openfn)(unsigned, const struct selinux_opt *,
					 unsigned) =
		dlsym(library, "selabel_open");
	int (*lookupfn)(struct selabel_handle *, char **, const char *, int) =
		dlsym(library, "selabel_lookup_raw");
	void (*closefn)(struct selabel_handle *) =
		dlsym(library, "selabel_close");
	assert(openfn && lookupfn && closefn);
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, file },
		{ SELABEL_OPT_BASEONLY, "1" },
		{ SELABEL_OPT_JIT, jit ? "1" : NULL },
	};
	struct selabel_handle *h = openfn(SELABEL_CTX_FILE, opts, 3);
	assert(h);
	for (unsigned i = 0; i < 3; i++) {
		char *ctx = NULL;
		assert(lookupfn(h, &ctx, "/test/leaf", 0) == 0);
		assert(!strcmp(ctx, "system_u:object_r:test_t:s0"));
		free(ctx);
	}
	closefn(h);
	return NULL;
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	char path[] = "/tmp/selinux-regex-context-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	FILE *fp = fdopen(fd, "we");
	assert(fp && fputs("/test/.* system_u:object_r:test_t:s0\n", fp) >= 0 &&
	       fclose(fp) == 0);
	file = path;
	unsigned cases = 0;
	for (jit = 0; jit < 2; jit++) {
		for (unsigned mode = 0; mode < 5; mode++) {
			for (unsigned cycle = 0; cycle < 3; cycle++) {
				memset(allocated, 0, sizeof(allocated));
				memset(freed, 0, sizeof(freed));
				memset(failures, 0, sizeof(failures));
				fail_compile = mode == 2 || mode == 4;
				fail_match = mode == 3 || mode == 4;
				library =
					dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
				if (!library) {
					fprintf(stderr, "%s\n", dlerror());
					abort();
				}
				if (mode) {
					for (unsigned repeat = 0; repeat < 3;
					     repeat++) {
						pthread_t thread;
						assert(pthread_create(
							       &thread, NULL,
							       worker,
							       NULL) == 0);
						assert(pthread_join(thread,
								    NULL) == 0);
					}
					assert(failures[0] ==
					       (mode == 2 || mode == 4));
					assert(failures[1] ==
					       (mode == 3 || mode == 4));
					assert(allocated[0] ==
					       (failures[0] ? 3U : 1U));
					assert(allocated[1] == !failures[1]);
					assert(allocated[0] - freed[0] ==
					       !failures[0]);
					assert(allocated[1] - freed[1] ==
					       !failures[1]);
				} else {
					assert(!allocated[0] && !allocated[1]);
				}
				/* Join first so all TLS destructors finish before unload. */
				assert(dlclose(library) == 0);
				assert(!dlopen(argv[1],
					       RTLD_NOW | RTLD_NOLOAD));
				assert(allocated[0] == freed[0] &&
				       allocated[1] == freed[1]);
				cases++;
			}
		}
	}
	assert(unlink(path) == 0);
	printf("regex-context-lifetime: %u unload scenarios passed\n", cases);
	return 0;
}
