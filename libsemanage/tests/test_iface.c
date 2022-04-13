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
#include "test_iface.h"

#define IFACE_COUNT 3

#define IFACE1_NAME "eth0"
#define IFACE1_IFCON "system_u:object_r:first_netif_t:s0"
#define IFACE1_MSGCON IFACE1_IFCON

#define IFACE2_NAME "eth1"
#define IFACE2_IFCON "system_u:object_r:second_netif_t:s0"
#define IFACE2_MSGCON IFACE2_IFCON

#define IFACE3_NAME "eth2"
#define IFACE3_IFCON "system_u:object_r:third_netif_t:s0"
#define IFACE3_MSGCON IFACE3_IFCON


/* iface_record.h */
static void test_iface_compare(void);
static void test_iface_compare2(void);
static void test_iface_key_create(void);
static void test_iface_key_extract(void);
static void test_iface_get_set_name(void);
static void test_iface_get_set_ifcon(void);
static void test_iface_get_set_msgcon(void);
static void test_iface_create(void);
static void test_iface_clone(void);

/* interfaces_policy.h */
static void test_iface_query(void);
static void test_iface_exists(void);
static void test_iface_count(void);
static void test_iface_iterate(void);
static void test_iface_list(void);

/* interfaces_local.h */
static void test_iface_modify_del_query_local(void);
static void test_iface_exists_local(void);
static void test_iface_count_local(void);
static void test_iface_iterate_local(void);
static void test_iface_list_local(void);

extern semanage_handle_t *sh;

int iface_test_init(void)
{
	if (create_test_store() < 0) {
		fprintf(stderr, "Could not create test store\n");
		return 1;
	}

	if (write_test_policy_from_file("test_iface.policy") < 0) {
		fprintf(stderr, "Could not write test policy\n");
		return 1;
	}

	return 0;
}

int iface_test_cleanup(void)
{
	if (destroy_test_store() < 0) {
		fprintf(stderr, "Could not destroy test store\n");
		return 1;
	}

	return 0;
}

int iface_add_tests(CU_pSuite suite)
{
	CU_add_test(suite, "iface_compare", test_iface_compare);
	CU_add_test(suite, "iface_compare2", test_iface_compare2);
	CU_add_test(suite, "iface_key_create", test_iface_key_create);
	CU_add_test(suite, "iface_key_extract", test_iface_key_extract);
	CU_add_test(suite, "iface_get_set_name", test_iface_get_set_name);
	CU_add_test(suite, "iface_get_set_ifcon", test_iface_get_set_ifcon);
	CU_add_test(suite, "iface_get_set_msgcon", test_iface_get_set_msgcon);
	CU_add_test(suite, "iface_create)", test_iface_create);
	CU_add_test(suite, "iface_clone);", test_iface_clone);

	CU_add_test(suite, "iface_query", test_iface_query);
	CU_add_test(suite, "iface_exists", test_iface_exists);
	CU_add_test(suite, "iface_count", test_iface_count);
	CU_add_test(suite, "iface_iterate", test_iface_iterate);
	CU_add_test(suite, "iface_list", test_iface_list);

	CU_add_test(suite, "iface_modify_del_query_local",
				test_iface_modify_del_query_local);
	CU_add_test(suite, "iface_exists_local", test_iface_exists_local);
	CU_add_test(suite, "iface_count_local", test_iface_count_local);
	CU_add_test(suite, "iface_iterate_local", test_iface_iterate_local);
	CU_add_test(suite, "iface_list_local", test_iface_list_local);

	return 0;
}

/* Helpers */

static semanage_iface_t *get_iface_nth(int idx)
{
	int res;
	semanage_iface_t **records;
	semanage_iface_t *iface;
	unsigned int count;

	if (idx == I_NULL)
		return NULL;

	res = semanage_iface_list(sh, &records, &count);

	CU_ASSERT_FATAL(res >= 0);
	CU_ASSERT_FATAL(count >= (unsigned int) idx + 1);

	iface = records[idx];

	for (unsigned int i = 0; i < count; i++)
		if (i != (unsigned int) idx)
			semanage_iface_free(records[i]);

	free(records);

	return iface;
}

static semanage_iface_key_t *get_iface_key_nth(int idx)
{
	semanage_iface_key_t *key;
	semanage_iface_t *iface;
	int res;

	if (idx == I_NULL)
		return NULL;

	iface = get_iface_nth(idx);
	res = semanage_iface_key_extract(sh, iface, &key);

	CU_ASSERT_FATAL(res >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	/* cleanup */
	semanage_iface_free(iface);

	return key;
}

static void add_local_iface(int idx)
{
	semanage_iface_t *iface;
	semanage_iface_key_t *key = NULL;

	iface = get_iface_nth(idx);

	CU_ASSERT_FATAL(semanage_iface_key_extract(sh, iface, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	CU_ASSERT_FATAL(semanage_iface_modify_local(sh, key, iface) >= 0);

	/* cleanup */
	semanage_iface_key_free(key);
	semanage_iface_free(iface);
}

static void delete_local_iface(int idx)
{
	semanage_iface_key_t *key = NULL;
	key = get_iface_key_nth(idx);
	CU_ASSERT_FATAL(semanage_iface_del_local(sh, key) >= 0);

	/* cleanup */
	semanage_iface_key_free(key);
}

/* Function semanage_iface_compare */
static void test_iface_compare(void)
{
	semanage_iface_t *iface = NULL;
	semanage_iface_key_t *key1 = NULL;
	semanage_iface_key_t *key2 = NULL;
	int res = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	iface = get_iface_nth(I_FIRST);
	key1 = get_iface_key_nth(I_FIRST);
	CU_ASSERT(semanage_iface_key_create(sh, "qwerty", &key2) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key2);

	/* test */
	res = semanage_iface_compare(iface, key1);
	CU_ASSERT(res == 0);
	res = semanage_iface_compare(iface, key2);
	CU_ASSERT(res != 0);

	/* cleanup */
	semanage_iface_free(iface);
	semanage_iface_key_free(key1);
	semanage_iface_key_free(key2);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_compare2 */
static void test_iface_compare2(void)
{
	semanage_iface_t *iface1 = NULL;
	semanage_iface_t *iface2 = NULL;
	semanage_iface_t *iface3 = NULL;
	int res = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	iface1 = get_iface_nth(I_FIRST);
	iface2 = get_iface_nth(I_FIRST);
	iface3 = get_iface_nth(I_SECOND);

	/* test */
	res = semanage_iface_compare2(iface1, iface2);
	CU_ASSERT(res == 0);
	res = semanage_iface_compare2(iface1, iface3);
	CU_ASSERT(res != 0);

	/* cleanup */
	semanage_iface_free(iface1);
	semanage_iface_free(iface2);
	semanage_iface_free(iface3);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_create */
static void test_iface_key_create(void)
{
	semanage_iface_key_t *key = NULL;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_iface_key_create(sh, "asdf", &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* cleanup */
	semanage_iface_key_free(key);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_extract */
static void test_iface_key_extract(void)
{
	semanage_iface_t *iface = NULL;
	semanage_iface_key_t *key = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	iface = get_iface_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_iface_key_extract(sh, iface, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* cleanup */
	semanage_iface_free(iface);
	semanage_iface_key_free(key);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_get_name, semanage_iface_set_name */
static void test_iface_get_set_name(void)
{
	semanage_iface_t *iface = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	iface = get_iface_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_iface_set_name(sh, iface, "my_asdf") == 0);
	CU_ASSERT_STRING_EQUAL(semanage_iface_get_name(iface), "my_asdf");

	/* cleanup */
	semanage_iface_free(iface);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_get_ifcon, semanage_iface_set_ifcon */
static void test_iface_get_set_ifcon(void)
{
	semanage_iface_t *iface = NULL;
	semanage_context_t *con1 = NULL;
	semanage_context_t *con2 = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	iface = get_iface_nth(I_FIRST);
	CU_ASSERT(semanage_context_from_string(sh,
			       "my_user_u:my_role_r:my_type_t:s0", &con1) >= 0);

	/* test */
	CU_ASSERT(semanage_iface_set_ifcon(sh, iface, con1) == 0);
	con2 = semanage_iface_get_ifcon(iface);
	CU_ASSERT_CONTEXT_EQUAL(con1, con2);

	/* cleanup */
	semanage_context_free(con1);
	semanage_iface_free(iface);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_get_msgcon, semanage_iface_set_msgcon */
static void test_iface_get_set_msgcon(void)
{
	semanage_iface_t *iface = NULL;
	semanage_context_t *con1 = NULL;
	semanage_context_t *con2 = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	iface = get_iface_nth(I_FIRST);
	CU_ASSERT(semanage_context_from_string(sh,
			       "my_user_u:my_role_r:my_type_t:s0", &con1) >= 0);

	/* test */
	CU_ASSERT(semanage_iface_set_msgcon(sh, iface, con1) == 0);
	con2 = semanage_iface_get_msgcon(iface);
	CU_ASSERT_CONTEXT_EQUAL(con1, con2);

	/* cleanup */
	semanage_context_free(con1);
	semanage_iface_free(iface);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_create */
static void test_iface_create(void)
{
	semanage_iface_t *iface = NULL;
	semanage_context_t *ifcon = NULL;
	semanage_context_t *msgcon = NULL;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_iface_create(sh, &iface) >= 0);
	CU_ASSERT(semanage_iface_set_name(sh, iface, "asdf") >= 0);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:type_t:s0",
					       &ifcon) >= 0);
	CU_ASSERT(semanage_iface_set_ifcon(sh, iface, ifcon) >= 0);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:type_t:s0",
					       &msgcon) >= 0);
	CU_ASSERT(semanage_iface_set_msgcon(sh, iface, msgcon) >= 0);

	/* cleanup */
	semanage_context_free(msgcon);
	semanage_context_free(ifcon);
	semanage_iface_free(iface);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_clone */
static void test_iface_clone(void)
{
	semanage_iface_t *iface = NULL;
	semanage_iface_t *iface_clone = NULL;
	semanage_context_t *ifcon = NULL;
	semanage_context_t *ifcon2 = NULL;
	semanage_context_t *msgcon = NULL;
	semanage_context_t *msgcon2 = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_iface_create(sh, &iface) >= 0);
	CU_ASSERT(semanage_iface_set_name(sh, iface, "asdf") >= 0);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:if_type_t:s0",
					       &ifcon) >= 0);
	CU_ASSERT(semanage_iface_set_ifcon(sh, iface, ifcon) >= 0);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:msg_type_t:s0",
					       &msgcon) >= 0);
	CU_ASSERT(semanage_iface_set_msgcon(sh, iface, msgcon) >= 0);

	/* test */
	CU_ASSERT(semanage_iface_clone(sh, iface, &iface_clone) >= 0);
	CU_ASSERT_STRING_EQUAL(semanage_iface_get_name(iface_clone), "asdf");

	ifcon2 = semanage_iface_get_ifcon(iface_clone);
	CU_ASSERT_CONTEXT_EQUAL(ifcon, ifcon2);

	msgcon2 = semanage_iface_get_msgcon(iface_clone);
	CU_ASSERT_CONTEXT_EQUAL(msgcon, msgcon2);

	/* cleanup */
	semanage_context_free(msgcon);
	semanage_context_free(ifcon);
	semanage_iface_free(iface);
	semanage_iface_free(iface_clone);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_query */
static void test_iface_query(void)
{
	semanage_iface_t *iface = NULL;
	semanage_iface_t *iface_exp = NULL;
	semanage_iface_key_t *key = NULL;
	semanage_context_t *con = NULL;
	semanage_context_t *con_exp = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	key = get_iface_key_nth(I_FIRST);
	iface_exp = get_iface_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_iface_query(sh, key, &iface) >= 0);
	CU_ASSERT_STRING_EQUAL(semanage_iface_get_name(iface),
		semanage_iface_get_name(iface_exp));

	con = semanage_iface_get_ifcon(iface);
	con_exp = semanage_iface_get_ifcon(iface_exp);
	CU_ASSERT_CONTEXT_EQUAL(con, con_exp);

	con = semanage_iface_get_msgcon(iface);
	con_exp = semanage_iface_get_msgcon(iface_exp);
	CU_ASSERT_CONTEXT_EQUAL(con, con_exp);

	/* cleanup */
	semanage_iface_key_free(key);
	semanage_iface_free(iface);
	semanage_iface_free(iface_exp);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_exists */
static void test_iface_exists(void)
{
	semanage_iface_key_t *key1 = NULL;
	semanage_iface_key_t *key2 = NULL;
	int resp = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	key1 = get_iface_key_nth(I_FIRST);
	CU_ASSERT(semanage_iface_key_create(sh, "asdf", &key2) >= 0);

	/* test */
	CU_ASSERT(semanage_iface_exists(sh, key1, &resp) >= 0);
	CU_ASSERT(resp);
	CU_ASSERT(semanage_iface_exists(sh, key2, &resp) >= 0);
	CU_ASSERT(!resp);

	/* cleanup */
	semanage_iface_key_free(key1);
	semanage_iface_key_free(key2);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_count */
static void test_iface_count(void)
{
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_iface_count(sh, &count) >= 0);
	CU_ASSERT(count == IFACE_COUNT);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_iterate */

unsigned int counter_iface_iterate = 0;

static int handler_iface_iterate(const semanage_iface_t *record, void *varg)
{
	counter_iface_iterate++;
	return 0;
}

static void test_iface_iterate(void)
{
	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	semanage_iface_iterate(sh, handler_iface_iterate, NULL);
	CU_ASSERT(counter_iface_iterate == IFACE_COUNT);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_list */
static void test_iface_list(void)
{
	semanage_iface_t **records = NULL;
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_iface_list(sh, &records, &count) >= 0);
	CU_ASSERT(count == IFACE_COUNT);

	for (unsigned int i = 0; i < count; i++)
		CU_ASSERT_PTR_NOT_NULL(records[i]);

	for (unsigned int i = 0; i < count; i++)
		semanage_iface_free(records[i]);

	free(records);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_iface_modify_local, semanage_iface_del_local,
 * semanage_iface_query_local
 */
static void test_iface_modify_del_query_local(void)
{
	semanage_iface_t *iface;
	semanage_iface_t *iface_local;
	semanage_iface_key_t *key = NULL;

	/* setup */
	setup_handle(SH_TRANS);
	iface = get_iface_nth(I_FIRST);
	CU_ASSERT(semanage_iface_key_extract(sh, iface, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* test */
	CU_ASSERT(semanage_iface_modify_local(sh, key, iface) >= 0);

	/* write changes to file */
	helper_commit();
	helper_begin_transaction();

	CU_ASSERT(semanage_iface_query_local(sh, key, &iface_local) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(iface_local);
	semanage_iface_free(iface_local);

	CU_ASSERT(semanage_iface_del_local(sh, key) >= 0);
	CU_ASSERT(semanage_iface_query_local(sh, key, &iface_local) < 0);

	/* cleanup */
	semanage_iface_key_free(key);
	semanage_iface_free(iface);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_iface_exists_local */
static void test_iface_exists_local(void)
{
	semanage_iface_key_t *key1 = NULL;
	semanage_iface_key_t *key2 = NULL;
	int resp = 42;

	/* setup */
	setup_handle(SH_TRANS);
	add_local_iface(I_FIRST);
	key1 = get_iface_key_nth(I_FIRST);
	key2 = get_iface_key_nth(I_SECOND);

	/* test */
	CU_ASSERT(semanage_iface_exists_local(sh, key1, &resp) >= 0);
	CU_ASSERT(resp);
	CU_ASSERT(semanage_iface_exists_local(sh, key2, &resp) >= 0);
	CU_ASSERT(!resp);

	/* cleanup */
	CU_ASSERT(semanage_iface_del_local(sh, key1) >= 0);
	semanage_iface_key_free(key1);
	semanage_iface_key_free(key2);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_iface_count_local */
static void test_iface_count_local(void)
{
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_TRANS);

	/* test */
	CU_ASSERT(semanage_iface_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 0);

	add_local_iface(I_FIRST);
	CU_ASSERT(semanage_iface_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 1);

	add_local_iface(I_SECOND);
	CU_ASSERT(semanage_iface_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 2);

	delete_local_iface(I_SECOND);
	CU_ASSERT(semanage_iface_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 1);

	delete_local_iface(I_FIRST);
	CU_ASSERT(semanage_iface_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 0);

	/* cleanup */
	cleanup_handle(SH_TRANS);
}

/* Function semanage_iface_iterate_local */
unsigned int counter_iface_iterate_local = 0;

static int handler_iface_iterate_local(const semanage_iface_t *record, void *varg)
{
	counter_iface_iterate_local++;
	return 0;
}

static void test_iface_iterate_local(void)
{
	/* setup */
	setup_handle(SH_TRANS);
	add_local_iface(I_FIRST);
	add_local_iface(I_SECOND);
	add_local_iface(I_THIRD);

	/* test */
	semanage_iface_iterate_local(sh, handler_iface_iterate_local, NULL);
	CU_ASSERT(counter_iface_iterate_local == 3);

	/* cleanup */
	delete_local_iface(I_FIRST);
	delete_local_iface(I_SECOND);
	delete_local_iface(I_THIRD);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_iface_list_local */
static void test_iface_list_local(void)
{
	semanage_iface_t **records = NULL;
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_TRANS);
	add_local_iface(I_FIRST);
	add_local_iface(I_SECOND);
	add_local_iface(I_THIRD);

	/* test */
	CU_ASSERT(semanage_iface_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 3);

	for (unsigned int i = 0; i < count; i++)
		CU_ASSERT_PTR_NOT_NULL(records[i]);

	/* cleanup */
	for (unsigned int i = 0; i < count; i++)
		semanage_iface_free(records[i]);
	free(records);

	delete_local_iface(I_FIRST);
	delete_local_iface(I_SECOND);
	delete_local_iface(I_THIRD);
	cleanup_handle(SH_TRANS);
}
