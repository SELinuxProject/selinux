/*
 * Authors: Jan Zarsky <jzarsky@redhat.com>
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "utilities.h"
#include "test_fcontext.h"

static const char FCONTEXTS[] =
    "/etc/selinux(/.*) -s system_u:object_r:first_t:s0\n"
    "/etc/selinux/targeted -- system_u:object_r:second_t:s0\n"
    "/etc/selinux(/.*) -b system_u:object_r:third_t:s0\n";
static const unsigned int FCONTEXTS_LEN = sizeof(FCONTEXTS);

#define FCONTEXTS_COUNT 3

#define FCONTEXT1_EXPR "/etc/selinux(/.*)"
#define FCONTEXT1_TYPE SEMANAGE_FCONTEXT_SOCK

#define FCONTEXT2_EXPR "/etc/selinux/targeted"
#define FCONTEXT2_TYPE SEMANAGE_FCONTEXT_REG

#define FCONTEXT_NONEXISTENT_EXPR "/asdf"
#define FCONTEXT_NONEXISTENT_TYPE SEMANAGE_FCONTEXT_ALL

/* fcontext_record.h */
static void test_fcontext_compare(void);
static void test_fcontext_compare2(void);
static void test_fcontext_key_create(void);
static void test_fcontext_key_extract(void);
static void test_fcontext_get_set_expr(void);
static void test_fcontext_get_set_type(void);
static void test_fcontext_get_type_str(void);
static void test_fcontext_get_set_con(void);
static void test_fcontext_create(void);
static void test_fcontext_clone(void);

/* fcontext_policy.h */
static void test_fcontext_query(void);
static void test_fcontext_exists(void);
static void test_fcontext_count(void);
static void test_fcontext_iterate(void);
static void test_fcontext_list(void);

/* fcontext_local.h */
static void test_fcontext_modify_del_local(void);
static void test_fcontext_query_local(void);
static void test_fcontext_exists_local(void);
static void test_fcontext_count_local(void);
static void test_fcontext_iterate_local(void);
static void test_fcontext_list_local(void);

static int write_file_contexts(const char *data, unsigned int data_len)
{
	FILE *fptr = fopen("test-policy/store/active/file_contexts", "w+");

	if (!fptr) {
		perror("fopen");
		return -1;
	}

	if (fwrite(data, data_len, 1, fptr) != 1) {
		perror("fwrite");
		fclose(fptr);
		return -1;
	}

	fclose(fptr);

	return 0;
}

int fcontext_test_init(void)
{
	if (create_test_store() < 0) {
		fprintf(stderr, "Could not create test store\n");
		return 1;
	}

	if (write_test_policy_from_file("test_fcontext.policy") < 0) {
		fprintf(stderr, "Could not write test policy\n");
		return 1;
	}

	if (write_file_contexts(FCONTEXTS, FCONTEXTS_LEN) < 0) {
		fprintf(stderr, "Could not write file contexts\n");
		return 1;
	}

	return 0;
}

int fcontext_test_cleanup(void)
{
	if (destroy_test_store() < 0) {
		fprintf(stderr, "Could not destroy test store\n");
		return 1;
	}

	return 0;
}

int fcontext_add_tests(CU_pSuite suite)
{
	CU_add_test(suite, "test_fcontext_compare", test_fcontext_compare);
	CU_add_test(suite, "test_fcontext_compare2", test_fcontext_compare2);
	CU_add_test(suite, "test_fcontext_key_create",
		    test_fcontext_key_create);
	CU_add_test(suite, "test_fcontext_key_extract",
		    test_fcontext_key_extract);
	CU_add_test(suite, "test_fcontext_get_set_expr",
		    test_fcontext_get_set_expr);
	CU_add_test(suite, "test_fcontext_get_set_type",
		    test_fcontext_get_set_type);
	CU_add_test(suite, "test_fcontext_get_type_str",
		    test_fcontext_get_type_str);
	CU_add_test(suite, "test_fcontext_get_set_con",
		    test_fcontext_get_set_con);
	CU_add_test(suite, "test_fcontext_create", test_fcontext_create);
	CU_add_test(suite, "test_fcontext_clone", test_fcontext_clone);

	CU_add_test(suite, "test_fcontext_query", test_fcontext_query);
	CU_add_test(suite, "test_fcontext_exists", test_fcontext_exists);
	CU_add_test(suite, "test_fcontext_count", test_fcontext_count);
	CU_add_test(suite, "test_fcontext_iterate", test_fcontext_iterate);
	CU_add_test(suite, "test_fcontext_list", test_fcontext_list);
	CU_add_test(suite, "test_fcontext_modify_del_local",
		    test_fcontext_modify_del_local);
	CU_add_test(suite, "test_fcontext_query_local",
		    test_fcontext_query_local);
	CU_add_test(suite, "test_fcontext_exists_local",
		    test_fcontext_exists_local);
	CU_add_test(suite, "test_fcontext_count_local",
		    test_fcontext_count_local);
	CU_add_test(suite, "test_fcontext_iterate_local",
		    test_fcontext_iterate_local);
	CU_add_test(suite, "test_fcontext_list_local",
		    test_fcontext_list_local);

	return 0;
}

/* Helpers */

static semanage_fcontext_t *get_fcontext_nth(int idx)
{
	semanage_fcontext_t **records;
	semanage_fcontext_t *fcontext;
	unsigned int count;

	if (idx == I_NULL)
		return NULL;

	CU_ASSERT_FATAL(semanage_fcontext_list(sh, &records, &count) >= 0);
	CU_ASSERT_FATAL(count >= (unsigned int) idx + 1);

	fcontext = records[idx];

	for (unsigned int i = 0; i < count; i++)
		if (i != (unsigned int) idx)
			semanage_fcontext_free(records[i]);

	free(records);

	return fcontext;
}

static semanage_fcontext_key_t *get_fcontext_key_nth(int idx)
{
	semanage_fcontext_key_t *key;
	semanage_fcontext_t *fcontext;

	if (idx == I_NULL)
		return NULL;

	fcontext = get_fcontext_nth(idx);

	CU_ASSERT_FATAL(semanage_fcontext_key_extract(sh, fcontext, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	semanage_fcontext_free(fcontext);

	return key;
}

static void add_local_fcontext(int fcontext_idx)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_key_t *key = NULL;

	CU_ASSERT_FATAL(fcontext_idx != I_NULL);

	fcontext = get_fcontext_nth(fcontext_idx);

	CU_ASSERT_FATAL(semanage_fcontext_key_extract(sh, fcontext, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	CU_ASSERT_FATAL(semanage_fcontext_modify_local(sh, key, fcontext) >= 0);

	/* cleanup */
	semanage_fcontext_key_free(key);
	semanage_fcontext_free(fcontext);
}

static void delete_local_fcontext(int fcontext_idx)
{
	semanage_fcontext_key_t *key = NULL;

	CU_ASSERT_FATAL(fcontext_idx != I_NULL);

	key = get_fcontext_key_nth(fcontext_idx);

	CU_ASSERT_FATAL(semanage_fcontext_del_local(sh, key) >= 0);

	semanage_fcontext_key_free(key);
}

static semanage_fcontext_key_t *get_fcontext_key_from_str(const char *str, int type)
{
	semanage_fcontext_key_t *key;
	int res;

	if (str == NULL)
		return NULL;

	res = semanage_fcontext_key_create(sh, str, type, &key);

	CU_ASSERT_FATAL(res >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	return key;
}

/* Function semanage_fcontext_compare */
static void test_fcontext_compare(void)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_key_t *key1;
	semanage_fcontext_key_t *key2;
	semanage_fcontext_key_t *key3;

	/* setup */
	setup_handle(SH_CONNECT);

	fcontext = get_fcontext_nth(I_FIRST);

	key1 = get_fcontext_key_nth(I_FIRST);
	key2 = get_fcontext_key_nth(I_SECOND);
	key3 = get_fcontext_key_nth(I_THIRD);

	/* test */
	CU_ASSERT(semanage_fcontext_compare(fcontext, key1) == 0);
	CU_ASSERT(semanage_fcontext_compare(fcontext, key2) < 0);
	CU_ASSERT(semanage_fcontext_compare(fcontext, key3) > 0);

	/* cleanup */
	semanage_fcontext_free(fcontext);
	semanage_fcontext_key_free(key1);
	semanage_fcontext_key_free(key2);
	semanage_fcontext_key_free(key3);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_compare2 */
static void test_fcontext_compare2(void)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_t *fcontext1;
	semanage_fcontext_t *fcontext2;
	semanage_fcontext_t *fcontext3;

	/* setup */
	setup_handle(SH_CONNECT);

	fcontext = get_fcontext_nth(I_FIRST);
	fcontext1 = get_fcontext_nth(I_FIRST);
	fcontext2 = get_fcontext_nth(I_SECOND);
	fcontext3 = get_fcontext_nth(I_THIRD);

	/* test */
	CU_ASSERT(semanage_fcontext_compare2(fcontext, fcontext1) == 0);
	CU_ASSERT(semanage_fcontext_compare2(fcontext, fcontext2) < 0);
	CU_ASSERT(semanage_fcontext_compare2(fcontext, fcontext3) > 0);

	/* cleanup */
	semanage_fcontext_free(fcontext);
	semanage_fcontext_free(fcontext1);
	semanage_fcontext_free(fcontext2);
	semanage_fcontext_free(fcontext3);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_key_create */
static void test_fcontext_key_create(void)
{
	semanage_fcontext_key_t *key = NULL;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_fcontext_key_create(sh, "", SEMANAGE_FCONTEXT_ALL,
					       &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	semanage_fcontext_key_free(key);

	key = NULL;

	CU_ASSERT(semanage_fcontext_key_create(sh, "testfcontext",
					     SEMANAGE_FCONTEXT_ALL, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	semanage_fcontext_key_free(key);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_key_extract */
static void test_fcontext_key_extract(void)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_key_t *key;

	/* setup */
	setup_handle(SH_CONNECT);
	fcontext = get_fcontext_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_fcontext_key_extract(sh, fcontext, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* cleanup */
	semanage_fcontext_key_free(key);
	semanage_fcontext_free(fcontext);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_get_expr, semanage_fcontext_set_expr */
static void test_fcontext_get_set_expr(void)
{
	semanage_fcontext_t *fcontext;
	const char *expr = NULL;
	const char *expr_exp = "/asdf";

	/* setup */
	setup_handle(SH_CONNECT);
	fcontext = get_fcontext_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_fcontext_set_expr(sh, fcontext, expr_exp) >= 0);
	expr = semanage_fcontext_get_expr(fcontext);
	CU_ASSERT_PTR_NOT_NULL(expr);
	assert(expr);
	CU_ASSERT_STRING_EQUAL(expr, expr_exp);

	/* cleanup */
	semanage_fcontext_free(fcontext);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_get_type, semanage_fcontext_set_type */
static void test_fcontext_get_set_type(void)
{
	semanage_fcontext_t *fcontext;
	int type_exp = SEMANAGE_FCONTEXT_SOCK;
	int type;

	/* setup */
	setup_handle(SH_CONNECT);
	fcontext = get_fcontext_nth(I_FIRST);

	/* test */
	semanage_fcontext_set_type(fcontext, type_exp);
	type = semanage_fcontext_get_type(fcontext);
	CU_ASSERT(type == type_exp);

	/* cleanup */
	semanage_fcontext_free(fcontext);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_fcontext_get_type_str */
static void helper_fcontext_get_type_str(int type, const char *exp_str)
{
	CU_ASSERT_STRING_EQUAL(semanage_fcontext_get_type_str(type), exp_str);
}

static void test_fcontext_get_type_str(void)
{
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_ALL, "all files");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_REG, "regular file");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_DIR, "directory");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_CHAR,
				     "character device");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_BLOCK, "block device");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_SOCK, "socket");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_LINK, "symbolic link");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_PIPE, "named pipe");

	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_ALL - 1, "????");
	helper_fcontext_get_type_str(SEMANAGE_FCONTEXT_PIPE + 1, "????");
}

/* Function semanage_fcontext_get_con, semanage_fcontext_set_con */
static void helper_fcontext_get_set_con(level_t level, int fcontext_idx,
				 const char *con_str)
{
	semanage_fcontext_t *fcontext;
	semanage_context_t *con = NULL;
	semanage_context_t *new_con = NULL;

	/* setup */
	setup_handle(level);
	fcontext = get_fcontext_nth(fcontext_idx);

	if (con_str != NULL) {
		CU_ASSERT(semanage_context_from_string(sh, con_str, &con) >= 0);
		CU_ASSERT_PTR_NOT_NULL(con);
	} else {
		con = NULL;
	}

	/* test */
	CU_ASSERT(semanage_fcontext_set_con(sh, fcontext, con) >= 0);
	new_con = semanage_fcontext_get_con(fcontext);

	if (con_str != NULL) {
		CU_ASSERT_CONTEXT_EQUAL(con, new_con);
	} else {
		CU_ASSERT_PTR_NULL(new_con);
	}

	/* cleanup */
	semanage_context_free(con);
	semanage_fcontext_free(fcontext);
	cleanup_handle(level);
}

static void test_fcontext_get_set_con(void)
{
	helper_fcontext_get_set_con(SH_CONNECT, I_FIRST, NULL);
	helper_fcontext_get_set_con(SH_CONNECT, I_FIRST,
				    "user_u:role_r:type_t:s0");
	helper_fcontext_get_set_con(SH_CONNECT, I_SECOND,
				    "user_u:role_r:type_t:s0");
	helper_fcontext_get_set_con(SH_TRANS, I_FIRST, NULL);
	helper_fcontext_get_set_con(SH_TRANS, I_FIRST,
				    "user_u:role_r:type_t:s0");
	helper_fcontext_get_set_con(SH_TRANS, I_SECOND,
				    "user_u:role_r:type_t:s0");
}

/* Function semanage_fcontext_create */
static void helper_fcontext_create(level_t level)
{
	semanage_fcontext_t *fcontext;

	/* setup */
	setup_handle(level);

	/* test */
	CU_ASSERT(semanage_fcontext_create(sh, &fcontext) >= 0);
	CU_ASSERT_PTR_NULL(semanage_fcontext_get_expr(fcontext));
	CU_ASSERT(semanage_fcontext_get_type(fcontext)
		  == SEMANAGE_FCONTEXT_ALL);
	CU_ASSERT_PTR_NULL(semanage_fcontext_get_con(fcontext));

	/* cleanup */
	semanage_fcontext_free(fcontext);
	cleanup_handle(level);
}

static void test_fcontext_create(void)
{
	helper_fcontext_create(SH_NULL);
	helper_fcontext_create(SH_HANDLE);
	helper_fcontext_create(SH_CONNECT);
	helper_fcontext_create(SH_TRANS);
}

/* Function semanage_fcontext_clone */
static void helper_fcontext_clone(level_t level, int fcontext_idx)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_t *fcontext_clone;
	const char *expr;
	const char *expr_clone;
	int type;
	int type_clone;
	semanage_context_t *con;
	semanage_context_t *con_clone;

	/* setup */
	setup_handle(level);
	fcontext = get_fcontext_nth(fcontext_idx);

	/* test */
	CU_ASSERT(semanage_fcontext_clone(sh, fcontext, &fcontext_clone) >= 0);

	expr = semanage_fcontext_get_expr(fcontext);
	expr_clone = semanage_fcontext_get_expr(fcontext_clone);
	CU_ASSERT_STRING_EQUAL(expr, expr_clone);

	type = semanage_fcontext_get_type(fcontext);
	type_clone = semanage_fcontext_get_type(fcontext_clone);
	CU_ASSERT_EQUAL(type, type_clone);

	con = semanage_fcontext_get_con(fcontext);
	con_clone = semanage_fcontext_get_con(fcontext_clone);
	CU_ASSERT_CONTEXT_EQUAL(con, con_clone);

	/* cleanup */
	semanage_fcontext_free(fcontext);
	semanage_fcontext_free(fcontext_clone);
	cleanup_handle(level);
}

static void test_fcontext_clone(void)
{
	helper_fcontext_clone(SH_CONNECT, I_FIRST);
	helper_fcontext_clone(SH_CONNECT, I_SECOND);
	helper_fcontext_clone(SH_TRANS, I_FIRST);
	helper_fcontext_clone(SH_TRANS, I_SECOND);
}

/* Function semanage_fcontext_query */
static void helper_fcontext_query(level_t level, const char *fcontext_expr,
			   int fcontext_type, int exp_res)
{
	semanage_fcontext_key_t *key;
	semanage_fcontext_t *resp = (void *) 42;
	int res;

	/* setup */
	setup_handle(level);
	key = get_fcontext_key_from_str(fcontext_expr, fcontext_type);

	/* test */
	res = semanage_fcontext_query(sh, key, &resp);

	if (exp_res >= 0) {
		CU_ASSERT(res >= 0);
		const char *expr = semanage_fcontext_get_expr(resp);
		CU_ASSERT_STRING_EQUAL(expr, fcontext_expr);
		semanage_fcontext_free(resp);
	} else {
		CU_ASSERT(res < 0);
		CU_ASSERT(resp == (void *) 42);
	}

	/* cleanup */
	semanage_fcontext_key_free(key);
	cleanup_handle(level);
}

static void test_fcontext_query(void)
{
	helper_fcontext_query(SH_CONNECT, FCONTEXT_NONEXISTENT_EXPR,
			      FCONTEXT_NONEXISTENT_TYPE, -1);
	helper_fcontext_query(SH_CONNECT, FCONTEXT2_EXPR, FCONTEXT1_TYPE, -1);
	helper_fcontext_query(SH_CONNECT, FCONTEXT1_EXPR, FCONTEXT1_TYPE, 1);
	helper_fcontext_query(SH_CONNECT, FCONTEXT2_EXPR, FCONTEXT2_TYPE, 1);
	helper_fcontext_query(SH_TRANS, FCONTEXT_NONEXISTENT_EXPR,
			      FCONTEXT_NONEXISTENT_TYPE, -1);
	helper_fcontext_query(SH_TRANS, FCONTEXT2_EXPR, FCONTEXT1_TYPE, -1);
	helper_fcontext_query(SH_TRANS, FCONTEXT1_EXPR, FCONTEXT1_TYPE, 1);
	helper_fcontext_query(SH_TRANS, FCONTEXT2_EXPR, FCONTEXT2_TYPE, 1);
}

/* Function semanage_fcontext_exists */
static void helper_fcontext_exists(level_t level, const char *fcontext_expr,
			    int fcontext_type, int exp_resp)
{
	semanage_fcontext_key_t *key;
	int resp;

	/* setup */
	setup_handle(level);
	key = get_fcontext_key_from_str(fcontext_expr, fcontext_type);

	/* test */
	CU_ASSERT(semanage_fcontext_exists(sh, key, &resp) >= 0);
	CU_ASSERT(resp == exp_resp);

	/* cleanup */
	semanage_fcontext_key_free(key);
	cleanup_handle(level);
}

static void test_fcontext_exists(void)
{
	helper_fcontext_exists(SH_CONNECT, FCONTEXT_NONEXISTENT_EXPR,
			       FCONTEXT_NONEXISTENT_TYPE, 0);
	helper_fcontext_exists(SH_CONNECT, FCONTEXT2_EXPR, FCONTEXT1_TYPE, 0);
	helper_fcontext_exists(SH_CONNECT, FCONTEXT1_EXPR, FCONTEXT1_TYPE, 1);
	helper_fcontext_exists(SH_CONNECT, FCONTEXT2_EXPR, FCONTEXT2_TYPE, 1);
	helper_fcontext_exists(SH_TRANS, FCONTEXT_NONEXISTENT_EXPR,
			       FCONTEXT_NONEXISTENT_TYPE, 0);
	helper_fcontext_exists(SH_TRANS, FCONTEXT2_EXPR, FCONTEXT1_TYPE, 0);
	helper_fcontext_exists(SH_TRANS, FCONTEXT1_EXPR, FCONTEXT1_TYPE, 1);
	helper_fcontext_exists(SH_TRANS, FCONTEXT2_EXPR, FCONTEXT2_TYPE, 1);
}

/* Function semanage_fcontext_count */
static void test_fcontext_count(void)
{
	unsigned int resp;

	/* handle */
	setup_handle(SH_HANDLE);
	CU_ASSERT(semanage_fcontext_count(sh, &resp) < 0);
	CU_ASSERT(semanage_fcontext_count(sh, NULL) < 0);
	cleanup_handle(SH_HANDLE);

	/* connect */
	resp = 0;
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_fcontext_count(sh, &resp) >= 0);
	CU_ASSERT(resp == FCONTEXTS_COUNT);
	cleanup_handle(SH_CONNECT);

	/* trans */
	resp = 0;
	setup_handle(SH_TRANS);
	CU_ASSERT(semanage_fcontext_count(sh, &resp) >= 0);
	CU_ASSERT(resp == FCONTEXTS_COUNT);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_fcontext_iterate */
static unsigned int counter_fcontext_iterate = 0;

static int handler_fcontext_iterate(const semanage_fcontext_t *record,
				    __attribute__((unused)) void *varg)
{
	CU_ASSERT_PTR_NOT_NULL(record);
	counter_fcontext_iterate++;
	return 0;
}

static void helper_fcontext_iterate_invalid(void)
{
	/* setup */
	setup_handle(SH_HANDLE);

	/* test */
	CU_ASSERT(semanage_fcontext_iterate(sh, &handler_fcontext_iterate,
				            NULL) < 0);
	CU_ASSERT(semanage_fcontext_iterate(sh, NULL, NULL) < 0);

	/* cleanup */
	cleanup_handle(SH_HANDLE);
}

static void helper_fcontext_iterate(level_t level)
{
	/* setup */
	setup_handle(level);
	counter_fcontext_iterate = 0;

	/* test */
	CU_ASSERT(semanage_fcontext_iterate(sh, &handler_fcontext_iterate,
					    NULL) >= 0);
	CU_ASSERT(counter_fcontext_iterate == FCONTEXTS_COUNT);

	/* cleanup */
	cleanup_handle(level);
}

static void test_fcontext_iterate(void)
{
	helper_fcontext_iterate_invalid();
	helper_fcontext_iterate(SH_CONNECT);
	helper_fcontext_iterate(SH_TRANS);
}

/* Function semanage_fcontext_list */
static void helper_fcontext_list_invalid(void)
{
	semanage_fcontext_t **records;
	unsigned int count;

	/* setup */
	setup_handle(SH_HANDLE);

	/* test */
	CU_ASSERT(semanage_fcontext_list(sh, &records, &count) < 0);
	CU_ASSERT(semanage_fcontext_list(sh, NULL, &count) < 0);
	CU_ASSERT(semanage_fcontext_list(sh, &records, NULL) < 0);

	/* cleanup */
	cleanup_handle(SH_HANDLE);
}

static void helper_fcontext_list(level_t level)
{
	semanage_fcontext_t **records;
	unsigned int count;

	/* setup */
	setup_handle(level);

	/* test */
	CU_ASSERT(semanage_fcontext_list(sh, &records, &count) >= 0);
	CU_ASSERT(count == FCONTEXTS_COUNT);

	for (unsigned int i = 0; i < count; i++)
		CU_ASSERT_PTR_NOT_NULL(records[i]);

	for (unsigned int i = 0; i < count; i++)
		semanage_fcontext_free(records[i]);

	free(records);

	/* cleanup */
	cleanup_handle(level);
}

static void test_fcontext_list(void)
{
	helper_fcontext_list_invalid();
	helper_fcontext_list(SH_CONNECT);
	helper_fcontext_list(SH_TRANS);
}

/* Function semanage_fcontext_modify_local, semanage_fcontext_del_local */
static void helper_fcontext_modify_del_local(level_t level, int fcontext_idx,
				      const char *con_str, int exp_res)
{
	semanage_fcontext_t *fcontext;
	semanage_fcontext_t *fcontext_local = NULL;
	semanage_fcontext_key_t *key = NULL;
	semanage_context_t *con = NULL;
	int res;

	/* setup */
	setup_handle(level);
	fcontext = get_fcontext_nth(fcontext_idx);
	CU_ASSERT(semanage_fcontext_key_extract(sh, fcontext, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	if (con_str != NULL) {
		CU_ASSERT(semanage_context_from_string(sh, con_str, &con) >= 0);
		CU_ASSERT_PTR_NOT_NULL(con);
	} else {
		con = NULL;
	}

	CU_ASSERT(semanage_fcontext_set_con(sh, fcontext, con) >= 0);

	/* test */
	res = semanage_fcontext_modify_local(sh, key, fcontext);

	if (exp_res >= 0) {
		CU_ASSERT(res >= 0);

		if (level == SH_TRANS) {
			helper_commit();
			helper_begin_transaction();
		}

		CU_ASSERT(semanage_fcontext_query_local(sh, key,
					                &fcontext_local) >= 0);
		CU_ASSERT(semanage_fcontext_compare2(fcontext_local,
						     fcontext) == 0);
		semanage_fcontext_free(fcontext_local);

		CU_ASSERT(semanage_fcontext_del_local(sh, key) >= 0);
		CU_ASSERT(semanage_fcontext_query_local(sh, key,
					                &fcontext_local) < 0);
	} else {
		CU_ASSERT(res < 0);
	}

	/* cleanup */
	semanage_context_free(con);
	semanage_fcontext_key_free(key);
	semanage_fcontext_free(fcontext);
	cleanup_handle(level);
}

static void test_fcontext_modify_del_local(void)
{
	helper_fcontext_modify_del_local(SH_CONNECT, I_FIRST,
					 "system_u:object_r:tmp_t:s0", -1);
	helper_fcontext_modify_del_local(SH_CONNECT, I_SECOND,
					 "system_u:object_r:tmp_t:s0", -1);
	helper_fcontext_modify_del_local(SH_TRANS, I_FIRST,
					 "system_u:object_r:tmp_t:s0", 1);
	helper_fcontext_modify_del_local(SH_TRANS, I_SECOND,
					 "system_u:object_r:tmp_t:s0", 1);
}

/* Function semanage_fcontext_query_local */
static void test_fcontext_query_local(void)
{
	semanage_fcontext_key_t *key = NULL;
	semanage_fcontext_t *resp = NULL;

	/* connect */
	setup_handle(SH_CONNECT);

	key = get_fcontext_key_nth(I_FIRST);
	CU_ASSERT(semanage_fcontext_query_local(sh, key, &resp) < 0);
	CU_ASSERT_PTR_NULL(resp);

	cleanup_handle(SH_CONNECT);

	/* transaction */
	setup_handle(SH_TRANS);

	semanage_fcontext_key_free(key);
	key = get_fcontext_key_nth(I_FIRST);
	CU_ASSERT(semanage_fcontext_query_local(sh, key, &resp) < 0);
	CU_ASSERT_PTR_NULL(resp);

	add_local_fcontext(I_FIRST);
	CU_ASSERT(semanage_fcontext_query_local(sh, key, &resp) >= 0);
	CU_ASSERT_PTR_NOT_NULL(resp);
	semanage_fcontext_free(resp);
	resp = NULL;

	semanage_fcontext_key_free(key);
	key = get_fcontext_key_nth(I_SECOND);
	add_local_fcontext(I_SECOND);
	CU_ASSERT(semanage_fcontext_query_local(sh, key, &resp) >= 0);
	CU_ASSERT_PTR_NOT_NULL(resp);
	semanage_fcontext_free(resp);
	resp = NULL;

	/* cleanup */
	semanage_fcontext_key_free(key);
	delete_local_fcontext(I_FIRST);
	delete_local_fcontext(I_SECOND);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_fcontext_exists_local */
static void test_fcontext_exists_local(void)
{
	int resp = -1;
	semanage_fcontext_key_t *key;

	/* setup */
	setup_handle(SH_TRANS);
	key = get_fcontext_key_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_fcontext_exists_local(sh, key, &resp) >= 0);
	CU_ASSERT(resp == 0);

	add_local_fcontext(I_FIRST);
	resp = -1;

	CU_ASSERT(semanage_fcontext_exists_local(sh, key, &resp) >= 0);
	CU_ASSERT(resp == 1);

	delete_local_fcontext(I_FIRST);
	resp = -1;

	CU_ASSERT(semanage_fcontext_exists_local(sh, key, &resp) >= 0);
	CU_ASSERT(resp == 0);

	resp = -1;

	CU_ASSERT(semanage_fcontext_exists_local(sh, NULL, &resp) >= 0);
	CU_ASSERT(resp == 0);

	/* cleanup */
	semanage_fcontext_key_free(key);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_fcontext_count_local */
static void test_fcontext_count_local(void)
{
	unsigned int resp;

	/* handle */
	setup_handle(SH_HANDLE);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) < 0);
	cleanup_handle(SH_HANDLE);

	/* connect */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) >= 0);
	CU_ASSERT(resp == 0);
	cleanup_handle(SH_CONNECT);

	/* transaction */
	setup_handle(SH_TRANS);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) >= 0);
	CU_ASSERT(resp == 0);

	add_local_fcontext(I_FIRST);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) >= 0);
	CU_ASSERT(resp == 1);

	add_local_fcontext(I_SECOND);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) >= 0);
	CU_ASSERT(resp == 2);

	delete_local_fcontext(I_SECOND);
	CU_ASSERT(semanage_fcontext_count_local(sh, &resp) >= 0);
	CU_ASSERT(resp == 1);

	/* cleanup */
	delete_local_fcontext(I_FIRST);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_fcontext_iterate_local */
static unsigned int counter_fcontext_iterate_local = 0;

static int handler_fcontext_iterate_local(const semanage_fcontext_t *record,
					  __attribute__((unused)) void *varg)
{
	CU_ASSERT_PTR_NOT_NULL(record);
	counter_fcontext_iterate_local++;
	return 0;
}

static void test_fcontext_iterate_local(void)
{
	/* handle */
	setup_handle(SH_HANDLE);

	CU_ASSERT(semanage_fcontext_iterate_local(sh,
				    &handler_fcontext_iterate_local, NULL) < 0);
	CU_ASSERT(semanage_fcontext_iterate_local(sh, NULL, NULL) < 0);

	cleanup_handle(SH_HANDLE);

	/* connect */
	setup_handle(SH_CONNECT);

	counter_fcontext_iterate_local = 0;
	CU_ASSERT(semanage_fcontext_iterate_local(sh,
				   &handler_fcontext_iterate_local, NULL) >= 0);
	CU_ASSERT(counter_fcontext_iterate_local == 0);
	CU_ASSERT(semanage_fcontext_iterate_local(sh, NULL, NULL) >= 0);

	cleanup_handle(SH_CONNECT);

	/* transaction */
	setup_handle(SH_TRANS);

	counter_fcontext_iterate_local = 0;
	CU_ASSERT(semanage_fcontext_iterate_local(sh,
				   &handler_fcontext_iterate_local, NULL) >= 0);
	CU_ASSERT(counter_fcontext_iterate_local == 0);

	add_local_fcontext(I_FIRST);
	counter_fcontext_iterate_local = 0;
	CU_ASSERT(semanage_fcontext_iterate_local(sh,
				   &handler_fcontext_iterate_local, NULL) >= 0);
	CU_ASSERT(counter_fcontext_iterate_local == 1);

	add_local_fcontext(I_SECOND);
	counter_fcontext_iterate_local = 0;
	CU_ASSERT(semanage_fcontext_iterate_local(sh,
				   &handler_fcontext_iterate_local, NULL) >= 0);
	CU_ASSERT(counter_fcontext_iterate_local == 2);

	/* cleanup */
	delete_local_fcontext(I_FIRST);
	delete_local_fcontext(I_SECOND);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_fcontext_list_local */
static void test_fcontext_list_local(void)
{
	semanage_fcontext_t **records;
	unsigned int count;

	/* handle */
	setup_handle(SH_HANDLE);

	CU_ASSERT(semanage_fcontext_list_local(sh, &records, &count) < 0);
	CU_ASSERT(semanage_fcontext_list_local(sh, NULL, &count) < 0);
	CU_ASSERT(semanage_fcontext_list_local(sh, &records, NULL) < 0);

	cleanup_handle(SH_HANDLE);

	/* connect */
	setup_handle(SH_CONNECT);

	CU_ASSERT(semanage_fcontext_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 0);

	cleanup_handle(SH_CONNECT);

	/* transaction */
	setup_handle(SH_TRANS);

	CU_ASSERT(semanage_fcontext_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 0);

	add_local_fcontext(I_FIRST);
	CU_ASSERT(semanage_fcontext_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 1);
	CU_ASSERT_PTR_NOT_NULL(records[0]);
	semanage_fcontext_free(records[0]);
	free(records);

	add_local_fcontext(I_SECOND);
	CU_ASSERT(semanage_fcontext_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 2);
	CU_ASSERT_PTR_NOT_NULL(records[0]);
	CU_ASSERT_PTR_NOT_NULL(records[1]);
	semanage_fcontext_free(records[0]);
	semanage_fcontext_free(records[1]);
	free(records);

	/* cleanup */
	delete_local_fcontext(I_FIRST);
	delete_local_fcontext(I_SECOND);
	cleanup_handle(SH_TRANS);
}
