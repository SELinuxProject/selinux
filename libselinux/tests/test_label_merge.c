/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/label.h>
#include "label_file.h"

static unsigned int fail_at, merges, faults;
static bool use_regex, persistent;

void *__real_reallocarray(void *ptr, size_t n, size_t size);
void *__wrap_reallocarray(void *ptr, size_t n, size_t size);
void *__wrap_reallocarray(void *ptr, size_t n, size_t size)
{
	if (n == 2 && size == (use_regex ? sizeof(struct regex_spec) :
					   sizeof(struct literal_spec))) {
		merges++;
		if (fail_at &&
		    (merges == fail_at || (persistent && merges > fail_at))) {
			faults++;
			errno = ENOMEM;
			return NULL;
		}
	}
	return __real_reallocarray(ptr, n, size);
}

static void check_lookup(struct selabel_handle *handle, const char *prefix,
			 const char *stem, const char *type)
{
	char path[128], expected[128];
	char *context = NULL;
	assert(snprintf(path, sizeof(path), "%s/%s/file", prefix, stem) > 0);
	assert(snprintf(expected, sizeof(expected), "system_u:object_r:%s:s0",
			type) > 0);
	assert(selabel_lookup_raw(handle, &context, path, S_IFREG) == 0);
	assert(!strcmp(context, expected));
	free(context);
}

static void check_handle(struct selabel_handle *handle, const char *prefix)
{
	assert(handle);
	check_lookup(handle, prefix, "a", "local_t");
	check_lookup(handle, prefix, "b", "local_t");
	check_lookup(handle, prefix, "aa", "base_t");
	check_lookup(handle, prefix, "ab", "local_t");
	selabel_close(handle);
}

static void run_case(const char *compiler, bool regex, bool nested,
		     bool keep_text, unsigned int failure)
{
	char root[] = "/tmp/label-merge-XXXXXX";
	char base[256], local[256], binary[256];
	const char *prefix = nested ? "/outer/inner" : "";
	const char *suffix = regex ? ".*" : "";
	assert(mkdtemp(root));
	assert(snprintf(base, sizeof(base), "%s/fc", root) > 0);
	assert(snprintf(local, sizeof(local), "%s/fc.local", root) > 0);
	assert(snprintf(binary, sizeof(binary), "%s/fc.local.bin", root) > 0);
	FILE *fp = fopen(base, "w");
	assert(fp);
	assert(fprintf(fp,
		       "%s/a/file%s system_u:object_r:base_t:s0\n"
		       "%s/aa/file%s system_u:object_r:base_t:s0\n"
		       "%s/b/file%s system_u:object_r:base_t:s0\n",
		       prefix, suffix, prefix, suffix, prefix, suffix) > 0);
	assert(fclose(fp) == 0);
	fp = fopen(local, "w");
	assert(fp);
	assert(fprintf(fp,
		       "%s/a/file%s system_u:object_r:local_t:s0\n"
		       "%s/ab/file%s system_u:object_r:local_t:s0\n"
		       "%s/b/file%s system_u:object_r:local_t:s0\n",
		       prefix, suffix, prefix, suffix, prefix, suffix) > 0);
	assert(fclose(fp) == 0);
	pid_t pid = fork();
	int status;
	assert(pid >= 0);
	if (!pid) {
		execl(compiler, compiler, "-o", binary, local, (char *)NULL);
		_exit(127);
	}
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	struct stat sb;
	assert(stat(binary, &sb) == 0);
	struct timespec times[] = { sb.st_atim, sb.st_mtim };
	assert(utimensat(AT_FDCWD, local, times, 0) == 0);
	if (!keep_text)
		assert(unlink(local) == 0);
	use_regex = regex;
	persistent = failure == 3;
	fail_at = persistent ? 2 : failure;
	struct selinux_opt opt = { SELABEL_OPT_PATH, base };
	struct selabel_handle *handle = selabel_open(SELABEL_CTX_FILE, &opt, 1);
	assert(faults == (failure ? (persistent && !keep_text ? 2 : 1) : 0));
	if (persistent && !keep_text)
		assert(handle == NULL);
	else
		check_handle(handle, prefix);
	fail_at = 0;
	check_handle(selabel_open(SELABEL_CTX_FILE, &opt, 1), prefix);
	if (keep_text)
		assert(unlink(local) == 0);
	assert(unlink(base) == 0 && unlink(binary) == 0 && rmdir(root) == 0);
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int cases = 0;
	for (int regex = 0; regex < 2; regex++)
		for (int nested = 0; nested < 2; nested++)
			for (int text = 0; text < 2; text++)
				for (unsigned int failure = 0; failure < 4;
				     failure++) {
					pid_t pid = fork();
					int status;
					assert(pid >= 0);
					if (!pid) {
						alarm(20);
						run_case(argv[1], regex, nested,
							 text, failure);
						_exit(0);
					}
					assert(waitpid(pid, &status, 0) == pid);
					assert(WIFEXITED(status) &&
					       WEXITSTATUS(status) == 0);
					cases++;
				}
	printf("Label merge cleanup: %u cases passed.\n", cases);
	return 0;
}
