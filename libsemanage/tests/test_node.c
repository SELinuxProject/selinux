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
#include "test_node.h"

#define NODE_COUNT 3

#define NODE1_ADDR "192.168.0.0"
#define NODE1_MASK "255.255.255.0"
#define NODE1_PROTO SEPOL_PROTO_IP4
#define NODE1_CONTEXT "system_u:object_r:first_node_t:s0"

#define NODE2_ADDR "2001:db8:85a3::8a2e:370:7334"
#define NODE2_MASK "2001:db8:85a3::8a2e:370:7334"
#define NODE2_PROTO SEPOL_PROTO_IP6
#define NODE2_CONTEXT "system_u:object_r:second_node_t:s0"

#define NODE3_ADDR "127.0.0.1"
#define NODE3_MASK "255.255.0.0"
#define NODE3_PROTO SEPOL_PROTO_IP4
#define NODE3_CONTEXT "system_u:object_r:third_node_t:s0"

/* node_record.h */
static void test_node_compare(void);
static void test_node_compare2(void);
static void test_node_key_create(void);
static void test_node_key_extract(void);
static void test_node_get_set_addr(void);
static void test_node_get_set_addr_bytes(void);
static void test_node_get_set_mask(void);
static void test_node_get_set_mask_bytes(void);
static void test_node_get_set_proto(void);
static void test_node_get_proto_str(void);
static void test_node_get_set_con(void);
static void test_node_create(void);
static void test_node_clone(void);

/* nodes_policy.h */
static void test_node_query(void);
static void test_node_exists(void);
static void test_node_count(void);
static void test_node_iterate(void);
static void test_node_list(void);

/* nodes_local.h */
static void test_node_modify_del_query_local(void);
static void test_node_exists_local(void);
static void test_node_count_local(void);
static void test_node_iterate_local(void);
static void test_node_list_local(void);

int node_test_init(void)
{
	if (create_test_store() < 0) {
		fprintf(stderr, "Could not create test store\n");
		return 1;
	}

	if (write_test_policy_from_file("test_node.policy") < 0) {
		fprintf(stderr, "Could not write test policy\n");
		return 1;
	}

	return 0;
}

int node_test_cleanup(void)
{
	if (destroy_test_store() < 0) {
		fprintf(stderr, "Could destroy test store\n");
		return 1;
	}

	return 0;
}

int node_add_tests(CU_pSuite suite)
{
	CU_add_test(suite, "node_compare", test_node_compare);
	CU_add_test(suite, "node_compare2", test_node_compare2);
	CU_add_test(suite, "node_key_create", test_node_key_create);
	CU_add_test(suite, "node_key_extract", test_node_key_extract);
	CU_add_test(suite, "node_get_set_addr", test_node_get_set_addr);
	CU_add_test(suite, "node_get_set_addr_bytes",
		    test_node_get_set_addr_bytes);
	CU_add_test(suite, "node_get_set_mask", test_node_get_set_mask);
	CU_add_test(suite, "node_get_set_mask_bytes",
		    test_node_get_set_mask_bytes);
	CU_add_test(suite, "node_get_set_proto", test_node_get_set_proto);
	CU_add_test(suite, "node_get_proto_str", test_node_get_proto_str);
	CU_add_test(suite, "node_get_set_con", test_node_get_set_con);
	CU_add_test(suite, "node_create", test_node_create);
	CU_add_test(suite, "node_clone", test_node_clone);

	CU_add_test(suite, "node_query", test_node_query);
	CU_add_test(suite, "node_exists", test_node_exists);
	CU_add_test(suite, "node_count", test_node_count);
	CU_add_test(suite, "node_iterate", test_node_iterate);
	CU_add_test(suite, "node_list", test_node_list);

	CU_add_test(suite, "node_modify_del_query_local",
		    test_node_modify_del_query_local);
	CU_add_test(suite, "node_exists_local", test_node_exists_local);
	CU_add_test(suite, "node_count_local", test_node_count_local);
	CU_add_test(suite, "node_iterate_local", test_node_iterate_local);
	CU_add_test(suite, "node_list_local", test_node_list_local);

	return 0;
}

/* Helpers */

static semanage_node_t *get_node_nth(int idx)
{
	semanage_node_t **records;
	semanage_node_t *node;
	unsigned int count;

	if (idx == I_NULL)
		return NULL;

	CU_ASSERT_FATAL(semanage_node_list(sh, &records, &count) >= 0);
	CU_ASSERT_FATAL(count >= (unsigned int) idx + 1);

	node = records[idx];

	for (unsigned int i = 0; i < count; i++)
		if (i != (unsigned int) idx)
			semanage_node_free(records[i]);

	free(records);

	return node;
}

static semanage_node_key_t *get_node_key_nth(int idx)
{
	semanage_node_key_t *key;
	semanage_node_t *node;
	int res;

	if (idx == I_NULL)
		return NULL;

	node = get_node_nth(idx);

	res = semanage_node_key_extract(sh, node, &key);

	CU_ASSERT_FATAL(res >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	semanage_node_free(node);

	return key;
}

static void add_local_node(int idx)
{
	semanage_node_t *node;
	semanage_node_key_t *key = NULL;

	node = get_node_nth(idx);

	CU_ASSERT_FATAL(semanage_node_key_extract(sh, node, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);

	CU_ASSERT_FATAL(semanage_node_modify_local(sh, key, node) >= 0);

	/* cleanup */
	semanage_node_key_free(key);
	semanage_node_free(node);
}

static void delete_local_node(int idx)
{
	semanage_node_key_t *key = NULL;

	key = get_node_key_nth(idx);

	CU_ASSERT_FATAL(semanage_node_del_local(sh, key) >= 0);

	/* cleanup */
	semanage_node_key_free(key);
}

/* Function semanage_node_compare */
static void test_node_compare(void)
{
	semanage_node_t *node = NULL;
	semanage_node_key_t *key1 = NULL;
	semanage_node_key_t *key2 = NULL;
	int res = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	node = get_node_nth(I_FIRST);
	key1 = get_node_key_nth(I_FIRST);
	CU_ASSERT(semanage_node_key_create(sh, "192.168.0.1", "255.255.0.0",
					   SEMANAGE_PROTO_IP4, &key2) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key2);

	/* test */
	res = semanage_node_compare(node, key1);
	CU_ASSERT(res == 0);
	res = semanage_node_compare(node, key2);
	CU_ASSERT(res != 0);

	/* cleanup */
	semanage_node_free(node);
	semanage_node_key_free(key1);
	semanage_node_key_free(key2);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_compare2 */
static void test_node_compare2(void)
{
	semanage_node_t *node1 = NULL;
	semanage_node_t *node2 = NULL;
	semanage_node_t *node3 = NULL;
	int res = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	node1 = get_node_nth(I_FIRST);
	node2 = get_node_nth(I_FIRST);
	node3 = get_node_nth(I_SECOND);

	/* test */
	res = semanage_node_compare2(node1, node2);
	CU_ASSERT(res == 0);
	res = semanage_node_compare2(node1, node3);
	CU_ASSERT(res != 0);

	/* cleanup */
	semanage_node_free(node1);
	semanage_node_free(node2);
	semanage_node_free(node3);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_key_create */
static void test_node_key_create(void)
{
	semanage_node_key_t *key = NULL;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_node_key_create(sh, "127.0.0.1", "255.255.255.255",
					   SEMANAGE_PROTO_IP4, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* cleanup */
	semanage_node_key_free(key);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_key_extract */
static void test_node_key_extract(void)
{
	semanage_node_t *node = NULL;
	semanage_node_key_t *key = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	node = get_node_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_node_key_extract(sh, node, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* cleanup */
	semanage_node_free(node);
	semanage_node_key_free(key);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_addr, semanage_node_set_addr */
static void test_node_get_set_addr(void)
{
	semanage_node_t *node = NULL;
	char *addr = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);

	/* test */
	CU_ASSERT(semanage_node_set_addr(sh, node, SEMANAGE_PROTO_IP4,
					 "192.168.0.1") == 0);
	CU_ASSERT(semanage_node_get_addr(sh, node, &addr) >= 0);
	CU_ASSERT_PTR_NOT_NULL(addr);
	assert(addr);
	CU_ASSERT_STRING_EQUAL(addr, "192.168.0.1");

	/* cleanup */
	free(addr);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_addr_bytes, semanage_node_set_addr_bytes */
static void test_node_get_set_addr_bytes(void)
{
	semanage_node_t *node = NULL;
	char addr1[] = { 192, 168, 0, 1 };
	size_t addr1_size = sizeof(addr1);
	char *addr2 = NULL;
	size_t addr2_size = 0;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);

	/* test */
	CU_ASSERT(semanage_node_set_addr_bytes(sh, node, addr1,
					       addr1_size) == 0);
	CU_ASSERT(semanage_node_get_addr_bytes(sh, node, &addr2,
					       &addr2_size) >= 0);
	CU_ASSERT_PTR_NOT_NULL(addr2);
	assert(addr2);

	for (size_t i = 0; i < addr2_size; i++)
		CU_ASSERT(addr1[i] == addr2[i]);

	/* cleanup */
	free(addr2);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_mask, semanage_node_set_mask */
static void test_node_get_set_mask(void)
{
	semanage_node_t *node = NULL;
	char *mask = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);

	/* test */
	CU_ASSERT(semanage_node_set_mask(sh, node, SEMANAGE_PROTO_IP4,
					 "255.255.255.0") == 0);
	CU_ASSERT(semanage_node_get_mask(sh, node, &mask) >= 0);
	CU_ASSERT_PTR_NOT_NULL(mask);
	assert(mask);
	CU_ASSERT_STRING_EQUAL(mask, "255.255.255.0");

	/* cleanup */
	free(mask);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_mask_bytes, semanage_node_set_mask_bytes */
static void test_node_get_set_mask_bytes(void)
{
	semanage_node_t *node = NULL;
	char mask1[] = { 255, 255, 255, 0 };
	size_t mask1_size = sizeof(mask1);
	char *mask2 = NULL;
	size_t mask2_size = 0;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);

	/* test */
	CU_ASSERT(semanage_node_set_mask_bytes(sh, node, mask1,
					       mask1_size) == 0);
	CU_ASSERT(semanage_node_get_mask_bytes(sh, node, &mask2,
					       &mask2_size) >= 0);
	CU_ASSERT_PTR_NOT_NULL(mask2);
	assert(mask2);

	for (size_t i = 0; i < mask2_size; i++)
		CU_ASSERT(mask1[i] == mask2[i]);

	/* cleanup */
	free(mask2);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_proto, semanage_node_set_proto */
static void test_node_get_set_proto(void)
{
	semanage_node_t *node = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);

	/* test */
	semanage_node_set_proto(node, SEMANAGE_PROTO_IP4);
	CU_ASSERT(semanage_node_get_proto(node) == SEMANAGE_PROTO_IP4);

	/* cleanup */
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_get_proto_str */
static void test_node_get_proto_str(void)
{
	CU_ASSERT_STRING_EQUAL(semanage_node_get_proto_str(SEMANAGE_PROTO_IP4),
							   "ipv4");
	CU_ASSERT_STRING_EQUAL(semanage_node_get_proto_str(SEMANAGE_PROTO_IP6),
							   "ipv6");
}

/* Function semanage_node_get_con, semanage_node_set_con */
static void test_node_get_set_con(void)
{
	semanage_node_t *node = NULL;
	semanage_context_t *con1 = NULL;
	semanage_context_t *con2 = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);
	CU_ASSERT(semanage_context_from_string(sh,
			       "my_user_u:my_role_r:my_type_t:s0", &con1) >= 0);

	/* test */
	CU_ASSERT(semanage_node_set_con(sh, node, con1) == 0);
	con2 = semanage_node_get_con(node);
	CU_ASSERT_CONTEXT_EQUAL(con1, con2);

	/* cleanup */
	semanage_context_free(con1);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_create */
static void test_node_create(void)
{
	semanage_node_t *node = NULL;
	semanage_context_t *con = NULL;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);
	CU_ASSERT(semanage_node_set_addr(sh, node, SEMANAGE_PROTO_IP4,
					 "127.0.0.1") >= 0);
	CU_ASSERT(semanage_node_set_mask(sh, node, SEMANAGE_PROTO_IP4,
					 "255.255.255.0") >= 0);
	semanage_node_set_proto(node, SEMANAGE_PROTO_IP4);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:type_t:s0",
					       &con) >= 0);
	CU_ASSERT(semanage_node_set_con(sh, node, con) >= 0);

	/* cleanup */
	semanage_context_free(con);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_clone */
static void test_node_clone(void)
{
	semanage_node_t *node = NULL;
	semanage_node_t *node_clone = NULL;
	semanage_context_t *con = NULL;
	semanage_context_t *con2 = NULL;
	const char *addr1 = "127.0.0.1";
	char *addr2 = NULL;
	const char *mask1 = "255.255.255.0";
	char *mask2 = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	CU_ASSERT(semanage_node_create(sh, &node) >= 0);
	CU_ASSERT(semanage_node_set_addr(sh, node, SEMANAGE_PROTO_IP4,
					 addr1) >= 0);
	CU_ASSERT(semanage_node_set_mask(sh, node, SEMANAGE_PROTO_IP4,
					 mask1) >= 0);
	semanage_node_set_proto(node, SEMANAGE_PROTO_IP4);
	CU_ASSERT(semanage_context_from_string(sh, "user_u:role_r:type_t:s0",
					       &con) >= 0);
	CU_ASSERT(semanage_node_set_con(sh, node, con) >= 0);

	/* test */
	CU_ASSERT(semanage_node_clone(sh, node, &node_clone) >= 0);

	CU_ASSERT(semanage_node_get_addr(sh, node_clone, &addr2) >= 0);
	CU_ASSERT_PTR_NOT_NULL(addr2);
	assert(addr2);
	CU_ASSERT_STRING_EQUAL(addr1, addr2);

	CU_ASSERT(semanage_node_get_mask(sh, node_clone, &mask2) >= 0);
	CU_ASSERT_PTR_NOT_NULL(mask2);
	assert(mask2);
	CU_ASSERT_STRING_EQUAL(mask1, mask2);

	CU_ASSERT(semanage_node_get_proto(node_clone) == SEMANAGE_PROTO_IP4);

	con2 = semanage_node_get_con(node_clone);
	CU_ASSERT_CONTEXT_EQUAL(con, con2);

	/* cleanup */
	free(mask2);
	free(addr2);
	semanage_context_free(con);
	semanage_node_free(node);
	semanage_node_free(node_clone);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_query */
static void test_node_query(void)
{
	semanage_node_t *node = NULL;
	semanage_node_t *node_exp = NULL;
	semanage_node_key_t *key = NULL;
	char *str = NULL;
	char *str_exp = NULL;
	semanage_context_t *con = NULL;
	semanage_context_t *con_exp = NULL;

	/* setup */
	setup_handle(SH_CONNECT);
	key = get_node_key_nth(I_FIRST);
	node_exp = get_node_nth(I_FIRST);

	/* test */
	CU_ASSERT(semanage_node_query(sh, key, &node) >= 0);

	CU_ASSERT(semanage_node_get_addr(sh, node, &str) >= 0);
	CU_ASSERT(semanage_node_get_addr(sh, node_exp, &str_exp) >= 0);
	CU_ASSERT_STRING_EQUAL(str, str_exp);
	free(str);
	free(str_exp);

	CU_ASSERT(semanage_node_get_mask(sh, node, &str) >= 0);
	CU_ASSERT(semanage_node_get_mask(sh, node_exp, &str_exp) >= 0);
	CU_ASSERT_STRING_EQUAL(str, str_exp);
	free(str);
	free(str_exp);

	CU_ASSERT(semanage_node_get_proto(node) ==
			  semanage_node_get_proto(node_exp));

	con = semanage_node_get_con(node);
	con_exp = semanage_node_get_con(node_exp);
	CU_ASSERT_CONTEXT_EQUAL(con, con_exp);

	/* cleanup */
	semanage_node_key_free(key);
	semanage_node_free(node_exp);
	semanage_node_free(node);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_exists */
static void test_node_exists(void)
{
	semanage_node_key_t *key1 = NULL;
	semanage_node_key_t *key2 = NULL;
	int resp = 42;

	/* setup */
	setup_handle(SH_CONNECT);
	key1 = get_node_key_nth(I_FIRST);
	CU_ASSERT(semanage_node_key_create(sh, "1.2.3.4", "255.255.0.0",
					   SEMANAGE_PROTO_IP4, &key2) >= 0);

	/* test */
	CU_ASSERT(semanage_node_exists(sh, key1, &resp) >= 0);
	CU_ASSERT(resp);
	CU_ASSERT(semanage_node_exists(sh, key2, &resp) >= 0);
	CU_ASSERT(!resp);

	/* cleanup */
	semanage_node_key_free(key1);
	semanage_node_key_free(key2);
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_count */
static void test_node_count(void)
{
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_node_count(sh, &count) >= 0);
	CU_ASSERT(count == NODE_COUNT);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_iterate */
static unsigned int counter_node_iterate = 0;

static int handler_node_iterate(__attribute__((unused)) const semanage_node_t *record,
				__attribute__((unused)) void *varg)
{
	counter_node_iterate++;
	return 0;
}

static void test_node_iterate(void)
{
	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	semanage_node_iterate(sh, handler_node_iterate, NULL);
	CU_ASSERT(counter_node_iterate == NODE_COUNT);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_list */
static void test_node_list(void)
{
	semanage_node_t **records = NULL;
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_CONNECT);

	/* test */
	CU_ASSERT(semanage_node_list(sh, &records, &count) >= 0);
	CU_ASSERT(count == NODE_COUNT);

	for (unsigned int i = 0; i < count; i++)
		CU_ASSERT_PTR_NOT_NULL(records[i]);

	for (unsigned int i = 0; i < count; i++)
		semanage_node_free(records[i]);

	free(records);

	/* cleanup */
	cleanup_handle(SH_CONNECT);
}

/* Function semanage_node_modify_local, semanage_node_del_local,
 * semanage_node_query_local
 */
static void test_node_modify_del_query_local(void)
{
	semanage_node_t *node;
	semanage_node_t *node_local;
	semanage_node_t *node_tmp;
	semanage_node_key_t *key = NULL;
	semanage_node_key_t *key_tmp = NULL;

	/* setup */
	setup_handle(SH_TRANS);
	node = get_node_nth(I_FIRST);
	CU_ASSERT(semanage_node_key_extract(sh, node, &key) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key);

	/* add second record, so that semanage_node_compare2_qsort
	 * will be called
	 */
	node_tmp = get_node_nth(I_FIRST);

	CU_ASSERT(semanage_node_set_addr(sh, node_tmp, SEMANAGE_PROTO_IP4,
					 "10.0.0.1") >= 0);
	CU_ASSERT(semanage_node_key_extract(sh, node_tmp, &key_tmp) >= 0);
	CU_ASSERT_PTR_NOT_NULL(key_tmp);

	/* test */
	CU_ASSERT(semanage_node_modify_local(sh, key, node) >= 0);
	CU_ASSERT(semanage_node_modify_local(sh, key_tmp, node_tmp) >= 0);

	/* write changes to file */
	helper_commit();
	helper_begin_transaction();

	CU_ASSERT(semanage_node_query_local(sh, key, &node_local) >= 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(node_local);
	semanage_node_free(node_local);

	CU_ASSERT(semanage_node_del_local(sh, key) >= 0);
	CU_ASSERT(semanage_node_del_local(sh, key_tmp) >= 0);

	CU_ASSERT(semanage_node_query_local(sh, key, &node_local) < 0);

	/* cleanup */
	semanage_node_key_free(key_tmp);
	semanage_node_key_free(key);
	semanage_node_free(node);
	semanage_node_free(node_tmp);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_node_exists_local */
static void test_node_exists_local(void)
{
	semanage_node_key_t *key1 = NULL;
	semanage_node_key_t *key2 = NULL;
	int resp = 42;

	/* setup */
	setup_handle(SH_TRANS);
	add_local_node(I_FIRST);
	key1 = get_node_key_nth(I_FIRST);
	key2 = get_node_key_nth(I_SECOND);

	/* test */
	CU_ASSERT(semanage_node_exists_local(sh, key1, &resp) >= 0);
	CU_ASSERT(resp);
	CU_ASSERT(semanage_node_exists_local(sh, key2, &resp) >= 0);
	CU_ASSERT(!resp);

	/* cleanup */
	CU_ASSERT(semanage_node_del_local(sh, key1) >= 0);
	semanage_node_key_free(key1);
	semanage_node_key_free(key2);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_node_count_local */
static void test_node_count_local(void)
{
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_TRANS);

	/* test */
	CU_ASSERT(semanage_node_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 0);

	add_local_node(I_FIRST);
	CU_ASSERT(semanage_node_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 1);

	add_local_node(I_SECOND);
	CU_ASSERT(semanage_node_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 2);

	delete_local_node(I_SECOND);
	CU_ASSERT(semanage_node_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 1);

	delete_local_node(I_FIRST);
	CU_ASSERT(semanage_node_count_local(sh, &count) >= 0);
	CU_ASSERT(count == 0);

	/* cleanup */
	cleanup_handle(SH_TRANS);
}

/* Function semanage_node_iterate_local */
static unsigned int counter_node_iterate_local = 0;

static int handler_node_iterate_local(__attribute__((unused)) const semanage_node_t *record,
				      __attribute__((unused)) void *varg)
{
	counter_node_iterate_local++;
	return 0;
}

static void test_node_iterate_local(void)
{
	/* setup */
	setup_handle(SH_TRANS);
	add_local_node(I_FIRST);
	add_local_node(I_SECOND);
	add_local_node(I_THIRD);

	/* test */
	semanage_node_iterate_local(sh, handler_node_iterate_local, NULL);
	CU_ASSERT(counter_node_iterate_local == 3);

	/* cleanup */
	delete_local_node(I_FIRST);
	delete_local_node(I_SECOND);
	delete_local_node(I_THIRD);
	cleanup_handle(SH_TRANS);
}

/* Function semanage_node_list_local */
static void test_node_list_local(void)
{
	semanage_node_t **records = NULL;
	unsigned int count = 42;

	/* setup */
	setup_handle(SH_TRANS);
	add_local_node(I_FIRST);
	add_local_node(I_SECOND);
	add_local_node(I_THIRD);

	/* test */
	CU_ASSERT(semanage_node_list_local(sh, &records, &count) >= 0);
	CU_ASSERT(count == 3);

	for (unsigned int i = 0; i < count; i++)
		CU_ASSERT_PTR_NOT_NULL(records[i]);

	/* cleanup */
	for (unsigned int i = 0; i < count; i++)
		semanage_node_free(records[i]);

	free(records);

	delete_local_node(I_FIRST);
	delete_local_node(I_SECOND);
	delete_local_node(I_THIRD);
	cleanup_handle(SH_TRANS);
}
