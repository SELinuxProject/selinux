#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <assert.h>
#include <errno.h>
#include <pcre2.h>
#include <pthread.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned created, freed, assignments, mode, jit;
static void *live[128];
static char path[256];

static void track(void *p)
{
	assert(p && created < 128);
	live[created++] = p;
}

pcre2_match_data *__wrap_pcre2_match_data_create_8(uint32_t n,
						   pcre2_general_context *ctx);
pcre2_match_data *
__wrap_pcre2_match_data_create_from_pattern_8(const pcre2_code *code,
					      pcre2_general_context *ctx);
void __wrap_pcre2_match_data_free_8(pcre2_match_data *p);
int __wrap_pthread_setspecific(pthread_key_t key, const void *p);
int __wrap_pthread_key_create(pthread_key_t *key, void (*destroy)(void *));

pcre2_match_data *__real_pcre2_match_data_create_8(uint32_t,
						   pcre2_general_context *);
pcre2_match_data *__wrap_pcre2_match_data_create_8(uint32_t n,
						   pcre2_general_context *ctx)
{
	if (mode == 4) {
		errno = ENOMEM;
		return NULL;
	}
	pcre2_match_data *p = __real_pcre2_match_data_create_8(n, ctx);
	track(p);
	return p;
}

pcre2_match_data *
__real_pcre2_match_data_create_from_pattern_8(const pcre2_code *,
					      pcre2_general_context *);
pcre2_match_data *
__wrap_pcre2_match_data_create_from_pattern_8(const pcre2_code *code,
					      pcre2_general_context *ctx)
{
	pcre2_match_data *p =
		__real_pcre2_match_data_create_from_pattern_8(code, ctx);
	track(p);
	return p;
}

void __real_pcre2_match_data_free_8(pcre2_match_data *);
void __wrap_pcre2_match_data_free_8(pcre2_match_data *p)
{
	if (p) {
		unsigned i;
		for (i = 0; i < created; i++)
			if (live[i] == p)
				break;
		assert(i < created);
		live[i] = NULL;
		freed++;
	}
	__real_pcre2_match_data_free_8(p);
}

int __real_pthread_setspecific(pthread_key_t, const void *);
int __wrap_pthread_setspecific(pthread_key_t key, const void *p)
{
	assignments++;
	if (mode == 1 || (mode == 2 && assignments == 1))
		return ENOMEM;
	return __real_pthread_setspecific(key, p);
}

int __real_pthread_key_create(pthread_key_t *, void (*)(void *));
int __wrap_pthread_key_create(pthread_key_t *key, void (*destroy)(void *))
{
	if (mode == 3)
		return EAGAIN;
	return __real_pthread_key_create(key, destroy);
}

static void *worker(void *unused)
{
	(void)unused;
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, path },
		{ SELABEL_OPT_BASEONLY, "1" },
		{ SELABEL_OPT_JIT, jit ? "1" : NULL },
	};
	struct selabel_handle *h = selabel_open(SELABEL_CTX_FILE, opts, 3);
	assert(h);
	for (unsigned i = 0; i < 32; i++) {
		char *context = NULL;
		int rc = selabel_lookup_raw(
			h, &context, i % 2 ? "/test/file" : "/test/missing", 0);
		if (i % 2) {
			assert(rc == 0 &&
			       !strcmp(context, "system_u:object_r:test_t:s0"));
			freecon(context);
		} else
			assert(rc == -1 && errno == ENOENT && !context);
	}
	selabel_close(h);
	return NULL;
}

int main(void)
{
	char dir[] = "/tmp/selinux-regex-tls-XXXXXX";
	assert(mkdtemp(dir));
	snprintf(path, sizeof(path), "%s/contexts", dir);
	FILE *fp = fopen(path, "we");
	assert(fp &&
	       fputs("/test/(file) system_u:object_r:test_t:s0\n", fp) >= 0 &&
	       fclose(fp) == 0);
	for (jit = 0; jit < 2; jit++) {
		for (mode = 0; mode < 5; mode++) {
			/* Isolate one-time TLS key initialization for key-failure cases. */
			pid_t pid = fork();
			assert(pid >= 0);
			if (!pid) {
				pthread_t thread;
				assert(pthread_create(&thread, NULL, worker,
						      NULL) == 0);
				assert(pthread_join(thread, NULL) == 0);
				assert(created == freed);
				assert(created == (mode == 0 ? 1U :
						   mode == 2 ? 2U :
							       32U));
				assert(assignments ==
				       (mode >= 3 ? 0U : created));
				exit(0);
			}
			int status;
			assert(waitpid(pid, &status, 0) == pid);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		}
	}
	assert(unlink(path) == 0 && rmdir(dir) == 0);
	puts("regex-tls: 10 scenarios, 320 lookups passed");
	return 0;
}
