/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sepol/policydb.h>
#include "semanage_conf.h"

static bool fail_token;
static unsigned failures;

char *__real_strdup(const char *s);
char *__wrap_strdup(const char *s);

char *__wrap_strdup(const char *s)
{
	if (fail_token && !strcmp(s, "true")) {
		failures++;
		errno = ENOMEM;
		return NULL;
	}
	return __real_strdup(s);
}

static semanage_conf_t *parse(const char *text)
{
	char path[] = "/tmp/semanage-config-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	FILE *fp = fdopen(fd, "w");
	assert(fp);
	assert(fputs(text, fp) >= 0);
	assert(fclose(fp) == 0);
	semanage_conf_t *conf = semanage_conf_parse(path);
	assert(unlink(path) == 0);
	return conf;
}

int main(void)
{
	const char *keys[] = { "module-store",	      "store-root",
			       "ro-store-root",	      "compiler-directory",
			       "ignore-module-cache", "policy-version",
			       "target-platform",     "expand-check",
			       "file-mode",	      "save-previous",
			       "save-linked",	      "disable-genhomedircon",
			       "usepasswd",	      "ignoredirs",
			       "handle-unknown",      "bzip-blocksize",
			       "bzip-small",	      "remove-hll",
			       "relabel_store",	      "optimize-policy",
			       "multiple-decls",      "sort-local-fcontexts" };
	const char *values[] = { "", "\"\"" };
	char version[32];
	snprintf(version, sizeof(version), "%d", sepol_policy_kern_vers_max());
	const char *valid[] = { "direct",
				"/var/lib/selinux",
				"/usr/lib/selinux",
				"/usr/libexec/selinux/hll",
				"true",
				version,
				"selinux",
				"true",
				"0644",
				"true",
				"true",
				"true",
				"true",
				"/home",
				"deny",
				"9",
				"true",
				"true",
				"true",
				"true",
				"true",
				"true" };
	assert(sizeof(valid) / sizeof(valid[0]) ==
	       sizeof(keys) / sizeof(keys[0]));
	unsigned cases = 0;
	for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		for (size_t j = 0; j < sizeof(values) / sizeof(values[0]);
		     j++) {
			char text[256];
			snprintf(text, sizeof(text), "%s = %s\n", keys[i],
				 values[j]);
			assert(parse(text) == NULL);
			semanage_conf_t *conf =
				parse("sort-local-fcontexts = true\n");
			assert(conf && conf->sort_local_fcontexts);
			semanage_conf_destroy(conf);
			cases += 2;
		}
		char text[256];
		snprintf(text, sizeof(text), "%s = %s\n", keys[i], valid[i]);
		semanage_conf_t *conf = parse(text);
		assert(conf);
		semanage_conf_destroy(conf);
		cases++;
	}
	for (size_t j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
		char text[256];
		snprintf(text, sizeof(text),
			 "[load_policy]\npath = /bin/true\nargs = %s\n[end]\n",
			 values[j]);
		semanage_conf_t *conf = parse(text);
		assert(conf && conf->load_policy &&
		       conf->load_policy->args == NULL);
		semanage_conf_destroy(conf);
		cases++;
	}
	fail_token = true;
	assert(parse("sort-local-fcontexts = true\n") == NULL);
	assert(failures == 1);
	fail_token = false;
	semanage_conf_t *conf = parse("sort-local-fcontexts = false\n");
	assert(conf && !conf->sort_local_fcontexts);
	semanage_conf_destroy(conf);
	printf("Configuration scalar arguments: %u cases passed.\n", cases + 2);
	return 0;
}
