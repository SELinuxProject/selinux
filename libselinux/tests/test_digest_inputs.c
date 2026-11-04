/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "label_internal.h"

static int fail_at, allocations;
void *__real_realloc(void *, size_t);
char *__real_strdup(const char *);
void *__wrap_realloc(void *p, size_t n);
char *__wrap_strdup(const char *p);

static bool fail(void)
{
	if (fail_at && ++allocations == fail_at) {
		errno = ENOMEM;
		return true;
	}
	return false;
}
void *__wrap_realloc(void *p, size_t n)
{
	return fail() ? NULL : __real_realloc(p, n);
}
char *__wrap_strdup(const char *p)
{
	return fail() ? NULL : __real_strdup(p);
}

static void destroy(struct selabel_digest *d)
{
	for (size_t i = 0; i < d->specfile_cnt; i++)
		free(d->specfile_list[i]);
	free(d->specfile_list);
	free(d->hashbuf);
}

int main(void)
{
	unsigned cases = 0;
	for (int failure = 1; failure <= 3; failure++) {
		struct selabel_digest d = { 0 };
		for (unsigned i = 0; i < 8; i++)
			assert(digest_add_specfile(&d, NULL, "a", 1, "first") ==
			       0);
		fail_at = failure;
		allocations = 0;
		assert(digest_add_specfile(&d, NULL, "b", 1, "next") == -1);
		assert(errno == ENOMEM && d.specfile_cnt == 8 &&
		       d.hashbuf_size == 8);
		assert(d.specfile_list[8] == NULL &&
		       !memcmp(d.hashbuf, "aaaaaaaa", 8));
		fail_at = 0;
		assert(digest_add_specfile(&d, NULL, "b", 1, "next") == 0);
		assert(d.specfile_cnt == 9 && d.hashbuf_size == 9 &&
		       d.specfile_list[9] == NULL);
		destroy(&d);
		cases++;
	}
	struct selabel_digest d = { 0 };
	assert(digest_add_specfile(&d, NULL, "", 0, "empty") == 0);
	FILE *fp = tmpfile();
	assert(fp);
	assert(digest_add_specfile(&d, fp, NULL, 1, "short") == -1);
	assert(d.specfile_cnt == 1 && d.hashbuf_size == 0 &&
	       d.specfile_list[1] == NULL);
	assert(fclose(fp) == 0);
	assert(digest_add_specfile(&d, NULL, "x", 1, "retry") == 0);
	destroy(&d);
	cases++;

	const unsigned counts[] = { 1, 4, 5, 8, 9, 16, 32, 253 };
	for (unsigned extras = 0; extras < 2; extras++) {
		char path[] = "/tmp/selabel-many-XXXXXX", aux[128];
		int fd = mkstemp(path);
		assert(fd >= 0);
		fp = fdopen(fd, "w");
		assert(fp &&
		       fputs("/probe system_u:object_r:test_t:s0\n", fp) >= 0);
		assert(fclose(fp) == 0);
		const char *suffixes[] = { ".subs", ".subs_dist", ".homedirs",
					   ".local" };
		if (extras) {
			for (unsigned i = 0; i < 4; i++) {
				snprintf(aux, sizeof(aux), "%s%s", path,
					 suffixes[i]);
				fp = fopen(aux, "w");
				assert(fp);
				assert(fputs(i < 2 ? "/other /elsewhere\n" :
						     "/extra system_u:object_r:extra_t:s0\n",
					     fp) >= 0);
				assert(fclose(fp) == 0);
			}
		}
		for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]);
		     c++) {
			struct selinux_opt opts[254];
			unsigned n = counts[c];
			for (unsigned i = 0; i < n; i++)
				opts[i] =
					(struct selinux_opt){ SELABEL_OPT_PATH,
							      path };
			opts[n] =
				(struct selinux_opt){ SELABEL_OPT_DIGEST, "1" };
			struct selabel_handle *h =
				selabel_open(SELABEL_CTX_FILE, opts, n + 1);
			assert(h);
			unsigned char *hash;
			char **files, *context = NULL;
			size_t len, num;
			assert(selabel_digest(h, &hash, &len, &files, &num) ==
			       0);
			assert(len == 20 && num == n + 4 * extras &&
			       files[num] == NULL);
			assert(selabel_lookup_raw(h, &context, "/probe", 0) ==
			       0);
			freecon(context);
			selabel_close(h);
			cases++;
		}
		for (unsigned i = 0; extras && i < 4; i++) {
			snprintf(aux, sizeof(aux), "%s%s", path, suffixes[i]);
			assert(unlink(aux) == 0);
		}
		assert(unlink(path) == 0);
	}
	printf("Dynamic digest inputs: %u cases passed.\n", cases);
	return 0;
}
