/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <selinux/label.h>

static void put(const char *path, const char *text)
{
	FILE *fp = fopen(path, "w");
	assert(fp && fputs(text, fp) >= 0 && fclose(fp) == 0);
}

int main(void)
{
	const char *rules[] = { "/stage/demo /\n", "/stage/* /\n",
				"/stage/*/*/files /\n",
				"/stage/* /intermediate\n" };
	const char *children[] = { "/stage/demo/usr/tool",
				   "/stage/demo/usr/tool",
				   "/stage/a/b/files/usr/tool",
				   "/stage/demo/usr/tool" };
	unsigned cases = 0;
	for (unsigned r = 0; r < 4; r++) {
		for (unsigned digest = 0; digest < 2; digest++) {
			char tmp[] = "/tmp/substitution-hash-XXXXXX", fc[128],
			     subs[128], dist[128];
			assert(mkdtemp(tmp));
			snprintf(fc, sizeof(fc), "%s/fc", tmp);
			snprintf(subs, sizeof(subs), "%s/fc.subs", tmp);
			snprintf(dist, sizeof(dist), "%s/fc.subs_dist", tmp);
			put(subs, rules[r]);
			if (r == 3)
				put(dist, "/intermediate /\n");
			uint8_t hashes[4][3][20];
			for (unsigned v = 0; v < 4; v++) {
				if (v == 3) {
					FILE *fp = fopen(subs, "a");
					assert(fp &&
					       fputs("/stage/new /other\n",
						     fp) >= 0 &&
					       fclose(fp) == 0);
				}
				put(fc,
				    v ? "/stage(/.*)? system_u:object_r:stage_t:s0\n/usr/tool system_u:object_r:new_t:s0\n/unrelated system_u:object_r:same_t:s0\n" :
					"/stage(/.*)? system_u:object_r:stage_t:s0\n/usr/tool system_u:object_r:old_t:s0\n/unrelated system_u:object_r:same_t:s0\n");
				struct selinux_opt opts[] = {
					{ SELABEL_OPT_PATH, fc },
					{ SELABEL_OPT_DIGEST,
					  digest ? "1" : NULL }
				};
				struct selabel_handle *h =
					selabel_open(SELABEL_CTX_FILE, opts, 2);
				assert(h);
				char *context = NULL;
				assert(selabel_lookup_raw(h, &context,
							  children[r], 0) == 0);
				assert(strstr(context,
					      v ? ":new_t:" : ":old_t:"));
				freecon(context);
				const char *keys[] = { "/stage", "/stage/demo",
						       "/unrelated" };
				for (unsigned k = 0; k < 3; k++) {
					assert(selabel_partial_match(h,
								     keys[k]));
					assert(selabel_hash_all_partial_matches(
						h, keys[k], hashes[v][k]));
				}
				assert(!selabel_partial_match(
					h, "/stage-sibling"));
				selabel_close(h);
			}
			for (unsigned k = 0; k < 3; k++) {
				assert((memcmp(hashes[0][k], hashes[1][k],
					       20) != 0) == (k < 2));
				assert(!memcmp(hashes[1][k], hashes[2][k], 20));
				assert((memcmp(hashes[2][k], hashes[3][k],
					       20) != 0) == (k < 2));
			}
			assert(unlink(fc) == 0 && unlink(subs) == 0);
			if (r == 3)
				assert(unlink(dist) == 0);
			assert(rmdir(tmp) == 0);
			cases++;
		}
	}
	printf("Substitution hashes: %u scenarios passed.\n", cases);
	return 0;
}
