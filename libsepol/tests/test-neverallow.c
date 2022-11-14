#define _GNU_SOURCE  /* vasprintf(3) */

#include "test-neverallow.h"

#include "helpers.h"
#include "test-common.h"

#include <sepol/debug.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/expand.h>

#include <stdio.h>
#include <stdarg.h>

extern int mls;

int neverallow_test_init(void)
{
	return 0;
}

int neverallow_test_cleanup(void)
{
	return 0;
}

static struct msg_list {
	char *msg;
	struct msg_list *next;
} *messages;

static void messages_clean(void)
{
	while (messages) {
		struct msg_list *n = messages->next;
		free(messages->msg);
		free(messages);
		messages = n;
	}
}

static void messages_check(unsigned count, const char *const expected[count])
{
	unsigned i;
	const struct msg_list *m = messages;

	for (i = 0; i < count; i++, m = m->next) {
		if (!m) {
			CU_FAIL("less messages than expected");
			fprintf(stderr, "\n<expected %u, got %u>\n", count, i);
			return;
		}

		if (strcmp(expected[i], m->msg) != 0) {
			CU_FAIL("messages differ from expected");
			fprintf(stderr, "\n<expected: '''%s''', got: '''%s'''>\n", expected[i], m->msg);
		}
	}

	if (m) {
		CU_FAIL("more messages than expected");
		fprintf(stderr, "\n<expected %u; next message: '''%s'''>\n", count, m->msg);
	}
}

__attribute__ ((format(printf, 3, 4)))
static void msg_handler(void *varg __attribute__ ((unused)),
			sepol_handle_t * handle __attribute__ ((unused)),
			const char *fmt, ...)
{
	char *msg;
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = vasprintf(&msg, fmt, ap);
	if (r < 0)
		CU_FAIL_FATAL("oom");
	va_end(ap);

	struct msg_list *new = malloc(sizeof(*new));
	if (!new)
		CU_FAIL_FATAL("oom");
	new->msg = msg;
	new->next = messages;
	messages = new;
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

static void test_neverallow_basic(void)
{
	policydb_t basemod, base_expanded;
	sepol_handle_t *handle;
	static const char *const expected_messages[] = {
		"30 neverallow failures occurred",
		"neverallow on line 53 of policies/test-neverallow/policy.conf.std (or line 53 of policies/test-neverallow/policy.conf.std) violated by allow test1_t test1_t:file { read };",
		"neverallow on line 60 of policies/test-neverallow/policy.conf.std (or line 60 of policies/test-neverallow/policy.conf.std) violated by allow test2_t test2_t:file { read write };",
		"neverallow on line 67 of policies/test-neverallow/policy.conf.std (or line 67 of policies/test-neverallow/policy.conf.std) violated by allow test3_t test3_t:file { read };",
		"neverallow on line 74 of policies/test-neverallow/policy.conf.std (or line 74 of policies/test-neverallow/policy.conf.std) violated by allow test4_t test4_t:file { read };",
		"neverallow on line 81 of policies/test-neverallow/policy.conf.std (or line 81 of policies/test-neverallow/policy.conf.std) violated by allow test5_t test5_t:file { read };",
		"neverallow on line 89 of policies/test-neverallow/policy.conf.std (or line 89 of policies/test-neverallow/policy.conf.std) violated by allow test6_1_t test6_1_t:file { read };",
		"neverallow on line 97 of policies/test-neverallow/policy.conf.std (or line 97 of policies/test-neverallow/policy.conf.std) violated by allow test7_1_t test7_1_t:file { read };",
		"neverallow on line 106 of policies/test-neverallow/policy.conf.std (or line 106 of policies/test-neverallow/policy.conf.std) violated by allow test8_t test8_t:file { write };",
		"neverallow on line 106 of policies/test-neverallow/policy.conf.std (or line 106 of policies/test-neverallow/policy.conf.std) violated by allow test8_t test8_t:file { read };",
		"neverallow on line 115 of policies/test-neverallow/policy.conf.std (or line 115 of policies/test-neverallow/policy.conf.std) violated by allow test9_t test9_t:file { read };",
		"neverallow on line 115 of policies/test-neverallow/policy.conf.std (or line 115 of policies/test-neverallow/policy.conf.std) violated by allow test9_t test9_t:file { write };",
		"neverallow on line 124 of policies/test-neverallow/policy.conf.std (or line 124 of policies/test-neverallow/policy.conf.std) violated by allow test10_1_t test10_1_t:file { read };",
		"neverallow on line 131 of policies/test-neverallow/policy.conf.std (or line 131 of policies/test-neverallow/policy.conf.std) violated by allow test11_t test11_t:process { dyntransition transition };",
		"neverallow on line 143 of policies/test-neverallow/policy.conf.std (or line 143 of policies/test-neverallow/policy.conf.std) violated by allow test12_3_t test12_1_t:file { getattr };",
		"neverallow on line 143 of policies/test-neverallow/policy.conf.std (or line 143 of policies/test-neverallow/policy.conf.std) violated by allow test12_3_t test12_2_t:file { getattr };",
		"neverallow on line 144 of policies/test-neverallow/policy.conf.std (or line 144 of policies/test-neverallow/policy.conf.std) violated by allow test12_3_t test12_1_t:file { open };",
		"neverallow on line 144 of policies/test-neverallow/policy.conf.std (or line 144 of policies/test-neverallow/policy.conf.std) violated by allow test12_2_t test12_1_t:file { open };",
		"neverallow on line 156 of policies/test-neverallow/policy.conf.std (or line 156 of policies/test-neverallow/policy.conf.std) violated by allow test13_1_t test13_1_t:file { read };",
		"neverallowxperm on line 174 of policies/test-neverallow/policy.conf.std (or line 174 of policies/test-neverallow/policy.conf.std) violated by\nallow test15_t test15_t:file { ioctl };",
		"neverallowxperm on line 182 of policies/test-neverallow/policy.conf.std (or line 182 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test16_t test16_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 198 of policies/test-neverallow/policy.conf.std (or line 198 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test18_t test18_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 206 of policies/test-neverallow/policy.conf.std (or line 206 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test19_t test19_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 216 of policies/test-neverallow/policy.conf.std (or line 216 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test20_a test20_a:file ioctl { 0x1111 };",
		"neverallowxperm on line 227 of policies/test-neverallow/policy.conf.std (or line 227 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test21_1_a test21_2_a:file ioctl { 0x1111 };",
		"neverallowxperm on line 237 of policies/test-neverallow/policy.conf.std (or line 237 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test22_t test22_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 247 of policies/test-neverallow/policy.conf.std (or line 247 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test23_t test23_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 257 of policies/test-neverallow/policy.conf.std (or line 257 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test24_t test24_a:file ioctl { 0x1111 };",
		"neverallowxperm on line 267 of policies/test-neverallow/policy.conf.std (or line 267 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test25_t test25_t:file ioctl { 0x1111 };",
		"neverallowxperm on line 277 of policies/test-neverallow/policy.conf.std (or line 277 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test26_a test26_a:file ioctl { 0x1111 };",
		"neverallowxperm on line 277 of policies/test-neverallow/policy.conf.std (or line 277 of policies/test-neverallow/policy.conf.std) violated by\nallowxperm test26_a test26_a:file ioctl { 0x1111 };",
	};

	if (policydb_init(&base_expanded))
		CU_FAIL_FATAL("Failed to initialize policy");

	if (test_load_policy(&basemod, POLICY_BASE, mls, "test-neverallow", "policy.conf"))
		CU_FAIL_FATAL("Failed to load policy");

	if (link_modules(NULL, &basemod, NULL, 0, 0))
		CU_FAIL_FATAL("Failed to link base module");

	if (expand_module(NULL, &basemod, &base_expanded, 0, 0))
		CU_FAIL_FATAL("Failed to expand policy");

	if ((handle = sepol_handle_create()) == NULL)
		CU_FAIL_FATAL("Failed to initialize handle");

	sepol_msg_set_callback(handle, msg_handler, NULL);

	if (check_assertions(handle, &base_expanded, base_expanded.global->branch_list->avrules) != -1)
		CU_FAIL("Assertions did not trigger");

	messages_check(ARRAY_SIZE(expected_messages), expected_messages);

	sepol_handle_destroy(handle);
	messages_clean();
	policydb_destroy(&basemod);
	policydb_destroy(&base_expanded);
}

int neverallow_add_tests(CU_pSuite suite)
{
	/*
	 * neverallow rules operate only on types and are unaffected by MLS
	 * (avoid adjusting the messages for std and mls)
	 */
	if (mls)
		return 0;

	if (NULL == CU_add_test(suite, "neverallow_basic", test_neverallow_basic)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
