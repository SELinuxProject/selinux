/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/label.h>

static const char *fail_suffix;
static bool default_path, tracking;
static unsigned int faults;
static void *allocations[256];
static size_t live;

static void track(void *ptr)
{
	if (tracking && ptr) {
		assert(live < sizeof(allocations) / sizeof(allocations[0]));
		allocations[live++] = ptr;
	}
}

void *__real_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size)
{
	void *ptr = __real_calloc(n, size);
	track(ptr);
	return ptr;
}

void __real_free(void *ptr);
void __wrap_free(void *ptr);
void __wrap_free(void *ptr)
{
	for (size_t i = 0; i < live; i++) {
		if (allocations[i] == ptr) {
			allocations[i] = allocations[--live];
			break;
		}
	}
	__real_free(ptr);
}

char *__real_strdup(const char *text);
char *__wrap_strdup(const char *text);
char *__wrap_strdup(const char *text)
{
	if (default_path && fail_suffix) {
		size_t len = strlen(text), suffix_len = strlen(fail_suffix);
		if (len > suffix_len && text[len - suffix_len - 1] == '.' &&
		    !strcmp(text + len - suffix_len, fail_suffix)) {
			faults++;
			errno = ENOMEM;
			return NULL;
		}
	}
	char *ptr = __real_strdup(text);
	track(ptr);
	return ptr;
}

static int allocate_path(char **out, const char *format, va_list args)
{
	if (fail_suffix && !strcmp(format, "%s.%s")) {
		va_list copy;
		va_copy(copy, args);
		(void)va_arg(copy, const char *);
		bool fail = !strcmp(va_arg(copy, const char *), fail_suffix);
		va_end(copy);
		if (fail) {
			faults++;
			/* POSIX leaves the output unspecified on failure. */
			*out = (char *)&faults;
			errno = ENOMEM;
			return -1;
		}
	}
	int rc = vasprintf(out, format, args);
	if (rc >= 0)
		track(*out);
	return rc;
}

int __wrap_asprintf(char **out, const char *format, ...);
int __wrap_asprintf(char **out, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int rc = allocate_path(out, format, args);
	va_end(args);
	return rc;
}

int __wrap___asprintf_chk(char **out, int flag, const char *format, ...);
int __wrap___asprintf_chk(char **out, int flag, const char *format, ...)
{
	(void)flag;
	va_list args;
	va_start(args, format);
	int rc = allocate_path(out, format, args);
	va_end(args);
	return rc;
}

static void write_context(const char *path, const char *context)
{
	FILE *fp = fopen(path, "w");
	assert(fp);
	assert(fprintf(fp, "/probe %s\n", context) > 0);
	assert(fclose(fp) == 0);
}

static void check_handle(struct selabel_handle *handle, const char *expected)
{
	char *context = NULL;
	assert(handle);
	assert(selabel_lookup_raw(handle, &context, "/probe", S_IFREG) == 0);
	assert(!strcmp(context, expected));
	free(context);
	selabel_close(handle);
	assert(live == 0);
}

static void run_case(bool use_default, bool base, bool digest, bool present,
		     const char *suffix)
{
	char root[] = "/tmp/label-init-oom-XXXXXX";
	char contexts[256], files[256], fc[256], homedirs[256], local[256];
	assert(mkdtemp(root));
	assert(snprintf(contexts, sizeof(contexts), "%s/contexts", root) > 0);
	assert(snprintf(files, sizeof(files), "%s/contexts/files", root) > 0);
	assert(snprintf(fc, sizeof(fc), "%s/contexts/files/file_contexts",
			root) > 0);
	assert(snprintf(homedirs, sizeof(homedirs), "%s.homedirs", fc) > 0);
	assert(snprintf(local, sizeof(local), "%s.local", fc) > 0);
	assert(mkdir(contexts, 0700) == 0 && mkdir(files, 0700) == 0);
	assert(selinux_set_policy_root(root) == 0);
	write_context(fc, "system_u:object_r:base_t:s0");
	if (present) {
		write_context(homedirs, "system_u:object_r:home_t:s0");
		write_context(local, "system_u:object_r:local_t:s0");
	}
	const char *expected = present && !base ?
				       "system_u:object_r:local_t:s0" :
				       "system_u:object_r:base_t:s0";
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, use_default ? NULL : fc },
		{ SELABEL_OPT_BASEONLY, base ? "1" : NULL },
		{ SELABEL_OPT_DIGEST, digest ? "1" : NULL },
	};
	default_path = use_default;
	tracking = true;
	fail_suffix = suffix;
	errno = 0;
	struct selabel_handle *handle = selabel_open(SELABEL_CTX_FILE, opts, 3);
	int error = errno;
	fail_suffix = NULL;
	if (suffix && !base) {
		assert(faults == 1 && handle == NULL && error == ENOMEM);
		assert(live == 0);
	} else {
		assert(faults == 0);
		check_handle(handle, expected);
	}
	/* A failed open must not poison a subsequent successful open. */
	check_handle(selabel_open(SELABEL_CTX_FILE, opts, 3), expected);
	tracking = false;
	if (present)
		assert(unlink(local) == 0 && unlink(homedirs) == 0);
	assert(unlink(fc) == 0 && rmdir(files) == 0);
	assert(rmdir(contexts) == 0 && rmdir(root) == 0);
}

int main(void)
{
	const char *suffixes[] = { NULL, "homedirs", "local" };
	unsigned int cases = 0;
	for (int def = 0; def < 2; def++)
		for (int base = 0; base < 2; base++)
			for (int digest = 0; digest < 2; digest++)
				for (int present = 0; present < 2; present++)
					for (size_t s = 0; s < 3; s++) {
						pid_t pid = fork();
						int status;
						assert(pid >= 0);
						if (!pid) {
							alarm(15);
							run_case(def, base,
								 digest,
								 present,
								 suffixes[s]);
							exit(0);
						}
						assert(waitpid(pid, &status,
							       0) == pid);
						assert(WIFEXITED(status) &&
						       WEXITSTATUS(status) ==
							       0);
						cases++;
					}
	printf("Label init OOM: %u cases passed.\n", cases);
	return 0;
}
