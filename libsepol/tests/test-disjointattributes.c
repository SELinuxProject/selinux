#define _GNU_SOURCE

#include "test-disjointattributes.h"

#include "helpers.h"
#include "test-common.h"

#include <sepol/debug.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/expand.h>

#include <stdio.h>
#include <stdarg.h>

extern int mls;

int disjointattrs_test_init(void)
{
	return 0;
}

int disjointattrs_test_cleanup(void)
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
			return;
		}

		if (strcmp(expected[i], m->msg) != 0) {
			CU_FAIL("messages differs from expected");
			fprintf(stderr, "\n<expected: '%s', got: '%s'>\n", expected[i], m->msg);
		}
	}

	if (m) {
		CU_FAIL("more messages than expected");
		fprintf(stderr, "\n<next message: '%s'>\n", m->msg);
	}
}

#ifdef __GNUC__
__attribute__ ((format(printf, 3, 4)))
#endif
static void msg_handler(void *varg __attribute__ ((unused)),
			sepol_handle_t * handle __attribute__ ((unused)),
			const char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);
	vasprintf(&msg, fmt, ap);
	va_end(ap);

	struct msg_list *new = malloc(sizeof(struct msg_list));
	new->msg = msg;
	new->next = messages;
	messages = new;
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

static void test_disjointattrs_single(void)
{
	policydb_t basemod, base_expanded;
	sepol_handle_t *handle;
	const char *const expected_messages[] = {
		"7 Disjoint Attributes Rule failures occurred",
		"Disjoint Attributes Rule violation, type test1_type associated with attributes test1_attr2 and test1_attr1",
		"Disjoint Attributes Rule violation, type test2_type3 associated with attributes test2_attr3 and test2_attr2",
		"Disjoint Attributes Rule violation, type test2_type4 associated with attributes test2_attr3 and test2_attr2",
		"Disjoint Attributes Rule violation, type test2_type1 associated with attributes test2_attr1 and test2_attr2",
		"Disjoint Attributes Rule violation, type test2_type4 associated with attributes test2_attr1 and test2_attr2",
		"Disjoint Attributes Rule violation, type test2_type2 associated with attributes test2_attr1 and test2_attr3",
		"Disjoint Attributes Rule violation, type test2_type4 associated with attributes test2_attr1 and test2_attr3",
	};

	if (policydb_init(&base_expanded))
		CU_FAIL_FATAL("Failed to initialize policy");

	if (test_load_policy(&basemod, POLICY_BASE, mls, "test-disjointattrs", "single.conf"))
		CU_FAIL_FATAL("Failed to load policy");

	if (link_modules(NULL, &basemod, NULL, 0, 0))
		CU_FAIL_FATAL("Failed to link base module");

	if (expand_module(NULL, &basemod, &base_expanded, 0, 0))
		CU_FAIL_FATAL("Failed to expand policy");

	if ((handle = sepol_handle_create()) == NULL)
		CU_FAIL_FATAL("Failed to initialize handle");

	sepol_msg_set_callback(handle, msg_handler, NULL);

	if (check_assertions(handle, &base_expanded, NULL) != -1)
		CU_FAIL("Assertions did not trigger");

	messages_check(ARRAY_SIZE(expected_messages), expected_messages);

	sepol_handle_destroy(handle);
	messages_clean();
	policydb_destroy(&basemod);
	policydb_destroy(&base_expanded);
}

#define NUM_MODS 3

static void test_disjointattrs_split(void)
{
	policydb_t basemod, base_expanded;
	policydb_t *modules[NUM_MODS];
	const char *policies[NUM_MODS] = { "split_module1.conf", "split_module2.conf", "split_module3.conf" };
	sepol_handle_t *handle;
	const char *const expected_messages[] = {
		"1 Disjoint Attributes Rule failures occurred",
		"Disjoint Attributes Rule violation, type test_type_t associated with attributes attr2 and attr1",
	};
	unsigned i;

	if (policydb_init(&base_expanded))
		CU_FAIL_FATAL("Failed to initialize policy");

	if (test_load_policy(&basemod, POLICY_BASE, mls, "test-disjointattrs", "split_base.conf"))
		CU_FAIL_FATAL("Failed to load policy");

	for (i = 0; i < NUM_MODS; i++) {
		modules[i] = calloc(1, sizeof(*modules[i]));
		if (!modules[i])
			CU_FAIL_FATAL("Failed to allocate module");

		if (test_load_policy(modules[i], POLICY_MOD, mls, "test-disjointattrs", policies[i]))
			CU_FAIL_FATAL("Failed to load module");
	}

	if (link_modules(NULL, &basemod, modules, 3, 0))
		CU_FAIL_FATAL("Failed to link base module");

	if (expand_module(NULL, &basemod, &base_expanded, 0, 0))
		CU_FAIL_FATAL("Failed to expand policy");

	if ((handle = sepol_handle_create()) == NULL)
		CU_FAIL_FATAL("Failed to initialize handle");

	sepol_msg_set_callback(handle, msg_handler, NULL);

	if (check_assertions(handle, &base_expanded, NULL) != -1)
		CU_FAIL("Assertions did not trigger");

	messages_check(ARRAY_SIZE(expected_messages), expected_messages);

	sepol_handle_destroy(handle);
	messages_clean();
	for (i = 0; i < NUM_MODS; i++) {
		policydb_destroy(modules[i]);
		free(modules[i]);
	}
	policydb_destroy(&basemod);
	policydb_destroy(&base_expanded);
}

int disjointattrs_add_tests(CU_pSuite suite)
{
	if (NULL == CU_add_test(suite, "disjointattrs_single", test_disjointattrs_single)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_add_test(suite, "disjointattrs_split", test_disjointattrs_split)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
