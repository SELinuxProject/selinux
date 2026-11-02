/* Authors: Eugenij Safonov <ja.safonau@protonmail.com>
 *
 * Copyright (C) 2026
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */

/*  The purpose of this file is to provide unit tests of the functions in:
 *
 *  libsemanage/src/path_subs.c
 *
 */

#include "path_subs.h"

#include "utilities.h"
#include "test_path_subs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* path_subs.h */
void test_path_subs_load(void);
void test_path_subs_load_file(void);
void test_path_subs_apply(void);
void test_path_subs_canonicalize(void);

static const char *const subs_file = "./test-path-subs.subs";

/* helper: write a subs file and load it (fails the test on error) */
static semanage_path_subs_t *load_rules(const char *content)
{
	FILE *fp = fopen(subs_file, "w");
	semanage_path_subs_t *rules = NULL;

	if (!fp)
		return NULL;
	fputs(content, fp);
	fclose(fp);

	if (semanage_path_subs_load(sh, subs_file, &rules) < 0)
		return NULL;

	return rules;
}

static void free_rules(semanage_path_subs_t **rules)
{
	semanage_path_subs_free(rules);
	unlink(subs_file);
}

/* helper: assert that applying "rules" to "path" yields "expected" */
static void assert_apply(const semanage_path_subs_t *rules, const char *path,
			 const char *expected)
{
	char *result = NULL;
	int rc = semanage_path_subs_apply(rules, path, &result);

	CU_ASSERT_EQUAL(rc, 0);
	if (expected) {
		CU_ASSERT_PTR_NOT_NULL_FATAL(result);
		CU_ASSERT_STRING_EQUAL(result, expected);
	} else {
		CU_ASSERT_PTR_NULL(result);
	}

	free(result);
}

/* helper: assert that canonicalizing through local+dist rules yields
 * "expected" */
static void assert_canonicalize(const semanage_path_subs_t *local,
				const semanage_path_subs_t *dist,
				const char *path, const char *expected)
{
	char *result = NULL;
	int rc = semanage_path_subs_canonicalize(local, dist, path, &result);

	CU_ASSERT_EQUAL(rc, 0);
	if (expected) {
		CU_ASSERT_PTR_NOT_NULL_FATAL(result);
		CU_ASSERT_STRING_EQUAL(result, expected);
	} else {
		CU_ASSERT_PTR_NULL(result);
	}

	free(result);
}

int path_subs_test_init(void)
{
	return 0;
}

int path_subs_test_cleanup(void)
{
	return 0;
}

int path_subs_add_tests(CU_pSuite suite)
{
	CU_add_test(suite, "semanage_path_subs_load", test_path_subs_load);
	CU_add_test(suite, "semanage_path_subs_load_file",
		    test_path_subs_load_file);
	CU_add_test(suite, "semanage_path_subs_apply", test_path_subs_apply);
	CU_add_test(suite, "semanage_path_subs_canonicalize",
		    test_path_subs_canonicalize);

	return 0;
}

/* Function semanage_path_subs_load */
void test_path_subs_load(void)
{
	semanage_path_subs_t *rules = NULL;
	FILE *fp;

	setup_handle(SH_HANDLE);

	/* missing file is not an error */
	unlink(subs_file);
	CU_ASSERT(semanage_path_subs_load(sh, subs_file, &rules) == 0);
	CU_ASSERT_PTR_NULL(rules);

	/* empty file yields no rules and no error */
	fp = fopen(subs_file, "w");
	CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
	fclose(fp);
	CU_ASSERT(semanage_path_subs_load(sh, subs_file, &rules) == 0);
	CU_ASSERT_PTR_NULL(rules);
	unlink(subs_file);

	/* file with only comments and blank lines */
	rules = load_rules("# comment\n\n   \n");
	CU_ASSERT_PTR_NULL(rules);

	/* comments and blank lines are ignored, arbitrary whitespace
	 * between alias and original is accepted */
	rules = load_rules("# comment\n\n   \n\t/foo\t /bar\n# another\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	CU_ASSERT_PTR_NULL(rules->next);
	CU_ASSERT_STRING_EQUAL(rules->alias, "/foo");
	CU_ASSERT_STRING_EQUAL(rules->original, "/bar");
	CU_ASSERT_EQUAL(rules->alias_len, strlen("/foo"));
	CU_ASSERT_EQUAL(rules->plen, strlen("/foo"));
	CU_ASSERT_FALSE(rules->has_wild);
	free_rules(&rules);

	/* rules are kept in reverse file order so the last matching
	 * rule in the file wins */
	rules = load_rules("/a /b\n/c /d\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	CU_ASSERT_STRING_EQUAL(rules->alias, "/c");
	CU_ASSERT_STRING_EQUAL(rules->original, "/d");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules->next);
	CU_ASSERT_STRING_EQUAL(rules->next->alias, "/a");
	CU_ASSERT_STRING_EQUAL(rules->next->original, "/b");
	CU_ASSERT_PTR_NULL(rules->next->next);
	free_rules(&rules);

	/* whole-component wildcards are loaded */
	rules = load_rules("/var/lib/extensions/* /\n/foo /bar\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	CU_ASSERT_STRING_EQUAL(rules->alias, "/foo");
	CU_ASSERT_STRING_EQUAL(rules->original, "/bar");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules->next);
	CU_ASSERT_STRING_EQUAL(rules->next->alias, "/var/lib/extensions/*");
	CU_ASSERT_STRING_EQUAL(rules->next->original, "/");
	CU_ASSERT_EQUAL(rules->next->plen, strlen("/var/lib/extensions/*") - 1);
	CU_ASSERT_TRUE(rules->next->has_wild);
	CU_ASSERT_PTR_NULL(rules->next->next);
	free_rules(&rules);

	/* a '*' that is not a whole path component is a load error */
	{
		FILE *fp2;

		unlink(subs_file);
		fp2 = fopen(subs_file, "w");
		CU_ASSERT_PTR_NOT_NULL_FATAL(fp2);
		fputs("/w*x/homes /home\n", fp2);
		fclose(fp2);
		rules = (void *)1;
		CU_ASSERT(semanage_path_subs_load(sh, subs_file, &rules) < 0);
		CU_ASSERT_PTR_NULL(rules);
		unlink(subs_file);
	}

	/* lines without an original are skipped */
	rules = load_rules("/foo\n/bar /baz\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	CU_ASSERT_PTR_NULL(rules->next);
	CU_ASSERT_STRING_EQUAL(rules->alias, "/bar");
	CU_ASSERT_STRING_EQUAL(rules->original, "/baz");
	free_rules(&rules);

	unlink(subs_file);
	cleanup_handle(SH_HANDLE);
}

/* Function semanage_path_subs_load_file */
void test_path_subs_load_file(void)
{
	semanage_path_subs_t *rules = NULL;
	FILE *fp;

	setup_handle(SH_HANDLE);

	/* load from an already opened stream */
	{
		static char empty[] = "# comment\n\n";

		fp = fmemopen(empty, sizeof(empty) - 1, "r");
		CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
		CU_ASSERT(semanage_path_subs_load_file(sh, fp, "<memory>",
						       &rules) == 0);
		CU_ASSERT_PTR_NULL(rules);
		fclose(fp);
	}

	{
		static char content[] = "/var/home /home\n";

		fp = fmemopen(content, sizeof(content) - 1, "r");
		CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
		CU_ASSERT(semanage_path_subs_load_file(sh, fp, "<memory>",
						       &rules) == 0);
		CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
		CU_ASSERT_STRING_EQUAL(rules->alias, "/var/home");
		CU_ASSERT_STRING_EQUAL(rules->original, "/home");
		semanage_path_subs_free(&rules);
		fclose(fp);
	}

	cleanup_handle(SH_HANDLE);
}

/* Function semanage_path_subs_apply */
void test_path_subs_apply(void)
{
	semanage_path_subs_t *rules;

	setup_handle(SH_HANDLE);

	rules = load_rules("/var/home /home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);

	/* exact alias */
	assert_apply(rules, "/var/home", "/home");
	/* subdirectory */
	assert_apply(rules, "/var/home/user", "/home/user");
	/* whole path component only: /var/homex is not under /var/home */
	assert_apply(rules, "/var/homex", NULL);
	assert_apply(rules, "/var/homex/user", NULL);
	/* unrelated path */
	assert_apply(rules, "/srv/home", NULL);

	free_rules(&rules);

	/* empty rule list */
	rules = NULL;
	assert_apply(rules, "/var/home", NULL);

	/* the last matching rule in the file wins */
	rules = load_rules("/a /b\n/a /c\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	assert_apply(rules, "/a/one", "/c/one");
	free_rules(&rules);

	/* original "/" must not produce a double slash */
	rules = load_rules("/var /\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	assert_apply(rules, "/var/home", "/home");
	free_rules(&rules);

	/* a '*' matches exactly one whole path component */
	rules = load_rules("/*/homes /home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	assert_apply(rules, "/w/homes", "/home");
	assert_apply(rules, "/xyz/homes", "/home");
	assert_apply(rules, "/w/x/homes", NULL); /* two components */
	assert_apply(rules, "/homes", NULL); /* missing component */
	assert_apply(rules, "/w/homesx", NULL); /* partial component */
	free_rules(&rules);

	/* a trailing '*' requires a further '/' after the matched
	 * component, so the entry remaps the contents of each named
	 * directory but not the directory itself */
	rules = load_rules("/var/lib/extensions/* /\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	assert_apply(rules, "/var/lib/extensions/foo/usr", "/usr");
	assert_apply(rules, "/var/lib/extensions/foo/etc/foo.conf",
		     "/etc/foo.conf");
	assert_apply(rules, "/var/lib/extensions/foo", NULL);
	assert_apply(rules, "/var/lib/extensions", NULL);
	free_rules(&rules);

	/* multiple '*' components */
	rules = load_rules("/sys/*/*/conf /etc/conf\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rules);
	assert_apply(rules, "/sys/a/b/conf", "/etc/conf");
	assert_apply(rules, "/sys/a/conf", NULL);
	free_rules(&rules);

	cleanup_handle(SH_HANDLE);
}

/* Function semanage_path_subs_canonicalize */
void test_path_subs_canonicalize(void)
{
	semanage_path_subs_t *local = NULL, *dist = NULL;

	setup_handle(SH_HANDLE);

	/* no rules at all */
	assert_canonicalize(NULL, NULL, "/var/home/user", NULL);

	/* distribution rule only */
	dist = load_rules("/var/home /home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(dist);
	assert_canonicalize(NULL, dist, "/var/home/user", "/home/user");
	assert_canonicalize(NULL, dist, "/srv/user", NULL);

	/* local rule only */
	local = load_rules("/srv/homes /var/home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(local);
	assert_canonicalize(local, NULL, "/srv/homes/user", "/var/home/user");

	/* local rule result is passed through the distribution rules */
	assert_canonicalize(local, dist, "/srv/homes/user", "/home/user");

	/* local match with no distribution match keeps the local result */
	free_rules(&dist);
	dist = load_rules("/other /elsewhere\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(dist);
	assert_canonicalize(local, dist, "/srv/homes/user", "/var/home/user");

	/* local rule shadows the distribution rule for matching paths */
	free_rules(&local);
	local = load_rules("/var/home /export/home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(local);
	assert_canonicalize(local, dist, "/var/home/user", "/export/home/user");

	/* wildcard local rule chained into a distribution rule */
	free_rules(&local);
	free_rules(&dist);
	local = load_rules("/srv/* /var/home\n");
	dist = load_rules("/var/home /home\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(local);
	CU_ASSERT_PTR_NOT_NULL_FATAL(dist);
	assert_canonicalize(local, dist, "/srv/alice/docs", "/home/docs");

	free_rules(&local);
	free_rules(&dist);

	cleanup_handle(SH_HANDLE);
}
