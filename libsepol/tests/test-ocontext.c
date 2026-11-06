#include "test-ocontext.h"

#include "helpers.h"

#include <arpa/inet.h>

extern int mls;

int ocontext_test_init(void)
{
	return 0;
}

int ocontext_test_cleanup(void)
{
	return 0;
}

/*
 * IPv4 node contexts are ordered from the most to the least specific mask.
 * The masks are stored in network byte order, so they must be compared as
 * such, also on little-endian hosts and for non-contiguous masks.
 */
static void test_ocontext_nodecon_order(void)
{
	policydb_t p;
	const ocontext_t *c;

	if (test_load_policy(&p, POLICY_BASE, mls, "test-ocontext",
			     "nodecon-order.conf"))
		CU_FAIL_FATAL("Failed to load policy");

	c = p.ocontexts[OCON_NODE];
	CU_ASSERT_PTR_NOT_NULL_FATAL(c);
	CU_ASSERT_EQUAL(c->u.node.mask, htonl(0xffff0000));

	c = c->next;
	CU_ASSERT_PTR_NOT_NULL_FATAL(c);
	CU_ASSERT_EQUAL(c->u.node.mask, htonl(0xff00ff00));

	CU_ASSERT_PTR_NULL(c->next);

	policydb_destroy(&p);
}

int ocontext_add_tests(CU_pSuite suite)
{
	if (NULL == CU_add_test(suite, "ocontext_nodecon_order",
				test_ocontext_nodecon_order)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	return 0;
}
