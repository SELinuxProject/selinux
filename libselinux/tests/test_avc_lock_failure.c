#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <selinux/avc.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void *live[2048];
static unsigned calls, outstanding, fail_at;
static unsigned custom_allocs, custom_gets, custom_frees;
static bool track, fail_enforce, fail_status;
void *__real_malloc(size_t size);
void __real_free(void *p);

void *__wrap_malloc(size_t size);
void __wrap_free(void *p);
int __wrap_security_getenforce(void);
int __wrap_selinux_status_open(int fallback);
void __wrap_selinux_status_close(void);

void *__wrap_malloc(size_t size)
{
	if (track && ++calls == fail_at) {
		errno = ENOMEM;
		return NULL;
	}
	void *p = __real_malloc(size);
	if (track && p) {
		unsigned i;
		for (i = 0; i < 2048 && live[i]; i++) {
		}
		assert(i < 2048);
		live[i] = p;
		outstanding++;
	}
	return p;
}

void __wrap_free(void *p)
{
	for (unsigned i = 0; p && i < 2048; i++) {
		if (live[i] != p)
			continue;
		live[i] = NULL;
		outstanding--;
		break;
	}
	__real_free(p);
}

int __wrap_security_getenforce(void)
{
	if (!fail_enforce)
		return 1;
	errno = EIO;
	return -1;
}

int __wrap_selinux_status_open(int fallback)
{
	(void)fallback;
	if (!fail_status)
		return 0;
	errno = EIO;
	return -1;
}

void __wrap_selinux_status_close(void)
{
}

/* Complete application callbacks may use a NULL token for a no-op lock. */
static void *custom_alloc(void)
{
	custom_allocs++;
	return NULL;
}

static void custom_get(void *p)
{
	assert(!p);
	custom_gets++;
}

static void custom_put(void *p)
{
	assert(!p);
}

static void custom_free(void *p)
{
	assert(!p);
	custom_frees++;
}

int main(void)
{
	for (unsigned stage = 0; stage < 6; stage++) {
		for (unsigned cycle = 0; cycle < 3; cycle++) {
			calls = 0;
			fail_at = stage < 4 ? stage + 1 : 0;
			fail_enforce = stage == 4;
			fail_status = stage == 5;
			track = true;
			errno = 0;
			assert(avc_open(NULL, 0) == -1);
			assert(errno == (stage < 4 ? ENOMEM : EIO));
			track = false;
			assert(outstanding == 0);
			calls = fail_at = 0;
			fail_enforce = fail_status = false;
			track = true;
			assert(avc_open(NULL, 0) == 0);
			track = false;
			security_id_t sid;
			assert(avc_context_to_sid_raw(
				       "system_u:object_r:retry_t:s0", &sid) ==
			       0);
			avc_destroy();
			assert(outstanding == 0);
		}
	}
	struct avc_lock_callback cb = { custom_alloc, custom_get, custom_put,
					custom_free };
	assert(avc_init("test", NULL, NULL, NULL, &cb) == 0);
	security_id_t sid;
	assert(avc_context_to_sid_raw("system_u:object_r:callback_t:s0",
				      &sid) == 0);
	avc_destroy();
	assert(custom_allocs == 2 && custom_frees == 2 && custom_gets);
	puts("AVC lock failure: 18 failure/retry cases and custom callback control passed");
	return 0;
}
