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
#include "test_handle.h"

static void test_handle_create(void);
static void test_connect(void);
static void test_disconnect(void);
static void test_transaction(void);
static void test_commit(void);
static void test_is_connected(void);
static void test_access_check(void);
static void test_is_managed(void);
static void test_mls_enabled(void);
static void test_msg_set_callback(void);
static void test_root(void);
static void test_select_store(void);

extern semanage_handle_t *sh;

int handle_test_init(void)
{
	if (create_test_store() < 0) {
		fprintf(stderr, "Could not create test store\n");
		return 1;
	}

	if (write_test_policy_from_file("test_handle.policy") < 0) {
		fprintf(stderr, "Could not write test policy\n");
		return 1;
	}

	return 0;
}

int handle_test_cleanup(void)
{
	if (destroy_test_store() < 0) {
		fprintf(stderr, "Could not destroy test store\n");
		return 1;
	}

	return 0;
}

int handle_add_tests(CU_pSuite suite)
{
	CU_add_test(suite, "test_handle_create", test_handle_create);
	CU_add_test(suite, "test_connect", test_connect);
	CU_add_test(suite, "test_disconnect", test_disconnect);
	CU_add_test(suite, "test_transaction", test_transaction);
	CU_add_test(suite, "test_commit", test_commit);
	CU_add_test(suite, "test_is_connected", test_is_connected);
	CU_add_test(suite, "test_access_check", test_access_check);
	CU_add_test(suite, "test_is_managed", test_is_managed);
	CU_add_test(suite, "test_mls_enabled", test_mls_enabled);
	CU_add_test(suite, "msg_set_callback", test_msg_set_callback);
	CU_add_test(suite, "test_root", test_root);
	CU_add_test(suite, "test_select_store", test_select_store);

	return 0;
}

/* Function semanage_handle_create */
static void test_handle_create(void)
{
	sh = semanage_handle_create();
	CU_ASSERT_PTR_NOT_NULL(sh);
	semanage_handle_destroy(sh);
}

/* Function semanage_connect */
static void test_connect(void)
{
	/* test handle created */
	setup_handle(SH_HANDLE);
	CU_ASSERT(semanage_connect(sh) >= 0);
	CU_ASSERT(semanage_disconnect(sh) >= 0);
	cleanup_handle(SH_HANDLE);

	/* test invalid store */
	setup_handle_invalid_store(SH_HANDLE);
	CU_ASSERT(semanage_connect(sh) < 0);
	cleanup_handle(SH_HANDLE);

	/* test normal use */
	setup_handle(SH_HANDLE);
	CU_ASSERT(semanage_connect(sh) >= 0);
	CU_ASSERT(semanage_disconnect(sh) >= 0);
	cleanup_handle(SH_HANDLE);
}

/* Function semanage_disconnect */
static void test_disconnect(void)
{
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_disconnect(sh) >= 0);
	cleanup_handle(SH_HANDLE);
}

/* Function semanage_begin_transaction */
static void test_transaction(void)
{
	/* test disconnected */
	setup_handle(SH_CONNECT);
	helper_disconnect();
	CU_ASSERT(semanage_begin_transaction(sh) < 0);

	cleanup_handle(SH_HANDLE);

	/* test normal use */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_begin_transaction(sh) >= 0);
	CU_ASSERT(semanage_commit(sh) >= 0);

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_commit */
static void test_commit(void)
{
	/* test without transaction */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_commit(sh) < 0);

	/* test with transaction */
	helper_begin_transaction();
	CU_ASSERT(semanage_commit(sh) >= 0);

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_is_connected */
static void test_is_connected(void)
{
	/* test disconnected */
	setup_handle(SH_HANDLE);
	CU_ASSERT(semanage_is_connected(sh) == 0);

	/* test connected */
	helper_connect();
	CU_ASSERT(semanage_is_connected(sh) == 1);

	/* test in transaction */
	helper_begin_transaction();
	CU_ASSERT(semanage_is_connected(sh) == 1);

	cleanup_handle(SH_TRANS);
}

/* Function semanage_access_check */
static void test_access_check(void)
{
	int res = 0;

	/* test with handle */
	setup_handle(SH_HANDLE);
	res = semanage_access_check(sh);
	CU_ASSERT(res == 0 || res == SEMANAGE_CAN_READ
		  || res == SEMANAGE_CAN_WRITE);
	cleanup_handle(SH_HANDLE);

	/* test with invalid store */
	setup_handle_invalid_store(SH_HANDLE);
	CU_ASSERT(semanage_access_check(sh) < 0);
	cleanup_handle(SH_HANDLE);

	/* test connected */
	setup_handle(SH_CONNECT);
	res = semanage_access_check(sh);
	CU_ASSERT(res == 0 || res == SEMANAGE_CAN_READ
		  || res == SEMANAGE_CAN_WRITE);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_is_managed */
static void test_is_managed(void)
{
	int res = 0;

	/* test with handle */
	setup_handle(SH_HANDLE);
	res = semanage_is_managed(sh);
	CU_ASSERT(res == 0 || res == 1);

	/* test connected */
	helper_connect();
	res = semanage_is_managed(sh);
	CU_ASSERT(res < 0);

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_mls_enabled */
static void test_mls_enabled(void)
{
	int res = 0;

	/* test with handle */
	setup_handle(SH_HANDLE);
	res = semanage_mls_enabled(sh);
	CU_ASSERT(res == 0 || res == 1);
	cleanup_handle(SH_HANDLE);

	/* test with invalid store */
	setup_handle_invalid_store(SH_HANDLE);
	CU_ASSERT(semanage_mls_enabled(sh) < 0);
	cleanup_handle(SH_HANDLE);

	/* test connected */
	setup_handle(SH_CONNECT);
	res = semanage_mls_enabled(sh);
	CU_ASSERT(res == 0 || res == 1);

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_set_callback */
int msg_set_callback_count = 0;

static void helper_msg_set_callback(void *varg, semanage_handle_t *handle,
			     const char *fmt, ...)
{
	msg_set_callback_count++;
}

static void test_msg_set_callback(void)
{
	setup_handle(SH_CONNECT);

	semanage_msg_set_callback(sh, helper_msg_set_callback, NULL);

	/* produce error message */
	semanage_commit(sh);
	CU_ASSERT(msg_set_callback_count == 1);
	semanage_msg_set_callback(sh, NULL, NULL);

	/* produce error message */
	semanage_commit(sh);
	CU_ASSERT(msg_set_callback_count == 1);

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_root, semanage_set_root */
static void helper_root(void)
{
	const char *root = NULL;

	CU_ASSERT(semanage_set_root("asdf") >= 0);
	root = semanage_root();
	CU_ASSERT_STRING_EQUAL(root, "asdf");

	CU_ASSERT(semanage_set_root("") >= 0);
	root = semanage_root();
	CU_ASSERT_STRING_EQUAL(root, "");
}

static void test_root(void)
{
	/* test without handle */
	setup_handle(SH_NULL);
	helper_root();

	/* test with handle */
	helper_handle_create();
	helper_root();

	/* test connected */
	helper_connect();
	helper_root();

	cleanup_handle(SH_CONNECT);
}

/* Function semanage_select_store */
static void helper_select_store(const char *name, enum semanage_connect_type type,
			 int exp_res)
{
	setup_handle(SH_HANDLE);

	/* FIXME: the storename parameter of semanage_select_store should be
	 * 'const char *'
	 */
	semanage_select_store(sh, (char *) name, type);

	int res = semanage_connect(sh);

	if (exp_res < 0) {
		CU_ASSERT(res < 0);
	} else {
		CU_ASSERT(res >= 0);
	}

	if (res >= 0)
		cleanup_handle(SH_CONNECT);
	else
		cleanup_handle(SH_HANDLE);
}

static void test_select_store(void)
{
	helper_select_store("asdf", SEMANAGE_CON_INVALID - 1, -1);
	helper_select_store("asdf", SEMANAGE_CON_POLSERV_REMOTE + 1, -1);
	helper_select_store("", SEMANAGE_CON_DIRECT, 0);

	helper_select_store("asdf", SEMANAGE_CON_INVALID, -1);
	helper_select_store("asdf", SEMANAGE_CON_DIRECT, 0);
	helper_select_store("asdf", SEMANAGE_CON_POLSERV_LOCAL, -1);
	helper_select_store("asdf", SEMANAGE_CON_POLSERV_REMOTE, -1);
}
