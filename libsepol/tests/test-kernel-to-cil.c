#include "test-kernel-to-cil.h"

#include "helpers.h"

#include <sepol/kernel_to_cil.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int mls;

int kernel_to_cil_test_init(void)
{
	return 0;
}

int kernel_to_cil_test_cleanup(void)
{
	return 0;
}

/*
 * checkpolicy assigns sensitivity and category aliases their own value slot
 * without a name in the value-to-name tables; the CIL writer must skip those
 * slots instead of emitting "(null)" declarations.
 */
static void test_kernel_to_cil_mls_aliases(void)
{
	policydb_t basemod, expanded;
	char *buf = NULL;
	size_t len = 0;
	FILE *out;

	if (test_load_policy(&basemod, POLICY_BASE, mls, "test-kernel-to-cil",
			     "mls-alias.conf"))
		CU_FAIL_FATAL("Failed to load policy");

	if (link_modules(NULL, &basemod, NULL, 0, 0))
		CU_FAIL_FATAL("Failed to link base module");

	if (policydb_init(&expanded))
		CU_FAIL_FATAL("Failed to initialize policy");

	if (expand_module(NULL, &basemod, &expanded, 0, 0))
		CU_FAIL_FATAL("Failed to expand policy");

	out = open_memstream(&buf, &len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(out);
	CU_ASSERT(sepol_kernel_policydb_to_cil(out, &expanded) == 0);
	CU_ASSERT_FATAL(fclose(out) == 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

	CU_ASSERT_PTR_NULL(strstr(buf, "(null)"));
	if (mls) {
		CU_ASSERT_PTR_NOT_NULL(
			strstr(buf, "(sensitivityorder (s0 s1))\n"));
		CU_ASSERT_PTR_NOT_NULL(strstr(buf, "(categoryorder (c0 c1))\n"));
		CU_ASSERT_PTR_NOT_NULL(
			strstr(buf, "(sensitivityaliasactual sens_alias s1)\n"));
		CU_ASSERT_PTR_NOT_NULL(
			strstr(buf, "(categoryaliasactual cat_alias c1)\n"));
	}

	free(buf);
	policydb_destroy(&basemod);
	policydb_destroy(&expanded);
}

int kernel_to_cil_add_tests(CU_pSuite suite)
{
	if (NULL == CU_add_test(suite, "kernel_to_cil_mls_aliases",
				test_kernel_to_cil_mls_aliases)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	return 0;
}
