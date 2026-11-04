#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *compiler;
static char paths[4][256];
static unsigned cases;

static int validate(char **ctx)
{
	assert(ctx && *ctx);
	if (strstr(*ctx, ":invalid_t:")) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static void put(unsigned index, const char *text, unsigned binary)
{
	FILE *fp = fopen(paths[index], "we");
	assert(fp && fputs(text, fp) >= 0 && fclose(fp) == 0);
	if (binary) {
		pid_t pid = fork();
		assert(pid >= 0);
		if (!pid) {
			execl(compiler, compiler, paths[index], NULL);
			_exit(127);
		}
		int status;
		assert(waitpid(pid, &status, 0) == pid);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		/* Force compiled-only loading rather than mtime-based selection. */
		assert(unlink(paths[index]) == 0);
	}
}

static void clear(void)
{
	for (unsigned i = 0; i < 4; i++) {
		char bin[sizeof(paths) + sizeof(".bin")];
		snprintf(bin, sizeof(bin), "%s.bin", paths[i]);
		assert(unlink(paths[i]) == 0 || errno == ENOENT);
		assert(unlink(bin) == 0 || errno == ENOENT);
	}
}

static struct selabel_handle *open_handle(unsigned multi, unsigned validating,
					  unsigned baseonly)
{
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_PATH, paths[0] },
		{ SELABEL_OPT_PATH, multi ? paths[1] : NULL },
		{ SELABEL_OPT_VALIDATE, validating ? "1" : NULL },
		{ SELABEL_OPT_BASEONLY, baseonly ? "1" : NULL },
		{ SELABEL_OPT_DIGEST, "1" },
	};
	return selabel_open(SELABEL_CTX_FILE, opts, 5);
}

static void lookup(struct selabel_handle *h, int type, const char *expected)
{
	char *context = NULL;
	assert(selabel_lookup_raw(h, &context, "/test", type) == 0);
	assert(strstr(context, expected));
	freecon(context);
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	compiler = argv[1];
	char dir[] = "/tmp/selinux-aux-dups-XXXXXX";
	assert(mkdtemp(dir));
	snprintf(paths[0], sizeof(paths[0]), "%s/contexts", dir);
	snprintf(paths[1], sizeof(paths[1]), "%s/second", dir);
	snprintf(paths[2], sizeof(paths[2]), "%s/contexts.local", dir);
	snprintf(paths[3], sizeof(paths[3]), "%s/contexts.homedirs", dir);
	union selinux_callback cb = { .func_validate = validate };
	selinux_set_callback(SELINUX_CB_VALIDATE, cb);
	for (unsigned binary = 0; binary < 2; binary++) {
		for (unsigned where = 0; where < 4; where++) {
			for (unsigned regex = 0; regex < 2; regex++) {
				for (unsigned pair = 0; pair < 3; pair++) {
					clear();
					char rules[512];
					const char *pattern =
						regex ? "/test(/.*)?" : "/test";
					/* ALL+DIR, REG+DIR, and identical REG keys. */
					snprintf(
						rules, sizeof(rules),
						"%s %s system_u:object_r:generic_t:s0\n"
						"%s %s system_u:object_r:directory_t:s0\n",
						pattern, pair ? "--" : "",
						pattern,
						pair == 2 ? "--" : "-d");
					put(0,
					    where ? "/other system_u:object_r:other_t:s0\n" :
						    rules,
					    binary);
					if (where)
						put(where, rules, binary);
					for (unsigned validating = 0;
					     validating < 2; validating++) {
						errno = 0;
						struct selabel_handle *h =
							open_handle(where == 1,
								    validating,
								    0);
						unsigned reject = validating &&
								  where < 2 &&
								  pair != 1;
						assert((h == NULL) == reject);
						if (h) {
							if (pair != 2)
								lookup(h,
								       S_IFREG,
								       ":generic_t:");
							if (pair == 1 ||
							    (regex &&
							     pair == 0))
								lookup(h,
								       S_IFDIR,
								       ":directory_t:");
							selabel_close(h);
						} else
							assert(errno == EINVAL);
						cases++;
					}
				}
			}
		}
		/* Identical patterns in separate primary inputs remain valid overrides. */
		clear();
		put(0, "/test(/.*)? system_u:object_r:first_t:s0\n", binary);
		put(1, "/test(/.*)? system_u:object_r:second_t:s0\n", binary);
		struct selabel_handle *h = open_handle(1, 1, 0);
		assert(h);
		lookup(h, S_IFREG, ":second_t:");
		selabel_close(h);
		cases++;
		for (unsigned where = 2; where < 4; where++) {
			clear();
			put(0, "/test(/.*)? system_u:object_r:first_t:s0\n",
			    binary);
			put(where,
			    "/test(/.*)? system_u:object_r:invalid_t:s0\n",
			    binary);
			h = open_handle(0, 1, 0);
			assert(!h && errno == EINVAL);
			cases++;
			h = open_handle(0, 1, 1);
			assert(h);
			lookup(h, S_IFREG, ":first_t:");
			selabel_close(h);
			cases++;
		}
	}
	clear();
	assert(rmdir(dir) == 0);
	printf("auxiliary-duplicates: %u cases passed\n", cases);
	return 0;
}
